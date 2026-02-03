#!/usr/bin/env python3
"""
DFIR Copilot by DFIRVault LLM Handler - Custom Splunk Search Command
Integrates with local Ollama LLM for DFIR analysis with RAG capabilities
"""

import sys
import json
import os
import time
from collections import OrderedDict
import requests
from splunklib.searchcommands import (
    dispatch, StreamingCommand, Configuration, Option, validators
)


@Configuration()
class LLMHandlerCommand(StreamingCommand):
    """
    Custom streaming command that sends Splunk events to a local LLM for analysis.
    
    Usage:
        | search index=security | llmhandler prompt="Analyze these security events" model="mistral" chunk_size=10
    """
    
    prompt = Option(
        doc='User prompt/question for the LLM',
        require=True,
        validate=validators.Match("prompt", r"^.+$")
    )
    
    model = Option(
        doc='LLM model to use (default: from config)',
        require=False,
        default=None
    )
    
    chunk_size = Option(
        doc='Number of events per chunk (default: 10)',
        require=False,
        default=10,
        validate=validators.Integer(minimum=1, maximum=1000)
    )
    
    analysis_mode = Option(
        doc='Analysis mode: summary, detailed, forensic, threat_intelligence',
        require=False,
        default='forensic',
        validate=validators.Set('summary', 'detailed', 'forensic', 'threat_intelligence')
    )
    
    max_tokens = Option(
        doc='Maximum tokens for LLM response',
        require=False,
        default=2000,
        validate=validators.Integer(minimum=100, maximum=8000)
    )
    
    temperature = Option(
        doc='LLM temperature (0.0-1.0)',
        require=False,
        default=0.7,
        validate=validators.Float(minimum=0.0, maximum=1.0)
    )

    def stream(self, records):
        """
        Main streaming method that processes events and sends them to LLM
        """
        try:
            # Load configuration
            config = self._load_config()
            
            # Override config with command options
            endpoint = config.get('endpoint', 'http://localhost:11434')
            model = self.model if self.model else config.get('model', 'mistral')
            chunk_size = int(self.chunk_size)
            
            # Collect events into chunks
            event_buffer = []
            chunk_number = 0
            previous_summary = None
            
            for record in records:
                event_buffer.append(record)
                
                # Process chunk when buffer is full
                if len(event_buffer) >= chunk_size:
                    chunk_number += 1
                    result = self._process_chunk(
                        event_buffer,
                        chunk_number,
                        previous_summary,
                        endpoint,
                        model,
                        config
                    )
                    
                    # Yield analysis result
                    yield self._create_result_record(result, chunk_number)
                    
                    # Store summary for context
                    previous_summary = result.get('summary', '')
                    
                    # Clear buffer
                    event_buffer = []
            
            # Process remaining events
            if event_buffer:
                chunk_number += 1
                result = self._process_chunk(
                    event_buffer,
                    chunk_number,
                    previous_summary,
                    endpoint,
                    model,
                    config
                )
                yield self._create_result_record(result, chunk_number)
            
            # Generate final synthesis if multiple chunks
            if chunk_number > 1:
                final_result = self._generate_final_synthesis(
                    chunk_number,
                    endpoint,
                    model,
                    config
                )
                yield self._create_result_record(final_result, 'FINAL')
                
        except Exception as e:
            self.logger.error(f"Error in llmhandler: {str(e)}")
            yield {
                '_time': time.time(),
                'llm_error': str(e),
                'llm_status': 'error'
            }
    
    def _load_config(self):
        """Load configuration from dfirvault.conf"""
        config = {
            'endpoint': 'http://localhost:11434',
            'model': 'mistral',
            'temperature': 0.7,
            'max_tokens': 2000,
            'timeout': 120,
            'chunk_size': 10,
            'analysis_mode': 'forensic',
            'system_prompt': 'You are a cybersecurity and DFIR expert assistant.'
        }
        
        try:
            # Try to load from app's local or default directory
            app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_paths = [
                os.path.join(app_root, 'local', 'dfirvault.conf'),
                os.path.join(app_root, 'default', 'dfirvault.conf')
            ]
            
            for config_path in config_paths:
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#') and not line.startswith('['):
                                if '=' in line:
                                    key, value = line.split('=', 1)
                                    config[key.strip()] = value.strip()
                    break
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
        
        return config
    
    def _process_chunk(self, events, chunk_number, previous_summary, endpoint, model, config):
        """
        Process a chunk of events with RAG pipeline
        """
        try:
            # Format events for LLM
            formatted_events = self._format_events(events)
            
            # Build context-aware prompt
            full_prompt = self._build_prompt(
                formatted_events,
                chunk_number,
                previous_summary,
                config
            )
            
            # Call LLM API
            response = self._call_ollama(
                endpoint,
                model,
                full_prompt,
                config
            )
            
            # Parse and structure response
            result = {
                'chunk': chunk_number,
                'event_count': len(events),
                'response': response,
                'summary': self._extract_summary(response),
                'status': 'success'
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error processing chunk {chunk_number}: {str(e)}")
            return {
                'chunk': chunk_number,
                'event_count': len(events),
                'error': str(e),
                'status': 'error'
            }
    
    def _format_events(self, events):
        """
        Format events for LLM consumption, preserving all fields and context
        """
        formatted = []
        
        for idx, event in enumerate(events, 1):
            # Create structured event representation
            event_str = f"Event {idx}:\n"
            
            # Add timestamp if available
            if '_time' in event:
                event_str += f"  Timestamp: {event['_time']}\n"
            
            # Add all fields in a structured format
            for key, value in sorted(event.items()):
                if not key.startswith('_') or key in ['_time', '_raw']:
                    event_str += f"  {key}: {value}\n"
            
            formatted.append(event_str)
        
        return "\n".join(formatted)
    
    def _build_prompt(self, formatted_events, chunk_number, previous_summary, config):
        """
        Build context-aware prompt with rolling summarization
        """
        system_prompt = config.get('system_prompt', 'You are a DFIR expert.')
        analysis_mode = self.analysis_mode or config.get('analysis_mode', 'forensic')
        
        # Mode-specific instructions
        mode_instructions = {
            'summary': 'Provide a concise summary of key findings.',
            'detailed': 'Provide detailed analysis of each significant event.',
            'forensic': 'Focus on forensic artifacts, timeline reconstruction, and evidence preservation. Identify potential indicators of compromise.',
            'threat_intelligence': 'Focus on threat actor TTPs, IOCs, and attribution indicators.'
        }
        
        prompt_parts = [
            f"System: {system_prompt}",
            f"\nAnalysis Mode: {analysis_mode}",
            f"\n{mode_instructions.get(analysis_mode, '')}",
            f"\nUser Question: {self.prompt}"
        ]
        
        # Add previous context for chunk continuity
        if previous_summary and chunk_number > 1:
            prompt_parts.append(f"\n\nPrevious Analysis Context (Chunk {chunk_number-1}):")
            prompt_parts.append(previous_summary)
            prompt_parts.append(f"\n\nNow analyzing Chunk {chunk_number}:")
        else:
            prompt_parts.append(f"\n\nAnalyzing Chunk {chunk_number}:")
        
        # Add current events
        prompt_parts.append(f"\n\n{formatted_events}")
        
        # Add specific instructions
        prompt_parts.append("\n\nProvide your analysis in a structured format:")
        prompt_parts.append("1. Key Findings")
        prompt_parts.append("2. Anomalies & IOCs")
        prompt_parts.append("3. Investigation Recommendations")
        prompt_parts.append("4. Summary (concise overview for context carryover)")
        
        return "\n".join(prompt_parts)
    
    def _call_ollama(self, endpoint, model, prompt, config):
        """
        Call Ollama API with error handling and retries
        """
        url = f"{endpoint}/api/generate"
        
        payload = {
            'model': model,
            'prompt': prompt,
            'stream': False,
            'options': {
                'temperature': float(self.temperature or config.get('temperature', 0.7)),
                'num_predict': int(self.max_tokens or config.get('max_tokens', 2000))
            }
        }
        
        timeout = int(config.get('timeout', 120))
        
        try:
            response = requests.post(url, json=payload, timeout=timeout)
            response.raise_for_status()
            
            result = response.json()
            return result.get('response', 'No response generated')
            
        except requests.exceptions.Timeout:
            raise Exception(f"Request to LLM timed out after {timeout} seconds")
        except requests.exceptions.ConnectionError:
            raise Exception(f"Cannot connect to Ollama at {endpoint}. Ensure Ollama is running.")
        except requests.exceptions.RequestException as e:
            raise Exception(f"LLM API error: {str(e)}")
    
    def _extract_summary(self, response):
        """
        Extract summary section from LLM response for context carryover
        """
        try:
            # Look for summary section
            if 'Summary' in response or 'SUMMARY' in response:
                lines = response.split('\n')
                summary_lines = []
                in_summary = False
                
                for line in lines:
                    if 'Summary' in line or 'SUMMARY' in line:
                        in_summary = True
                        continue
                    if in_summary:
                        if line.strip() and not line.startswith('#'):
                            summary_lines.append(line.strip())
                        if len(summary_lines) > 5:  # Limit summary length
                            break
                
                return ' '.join(summary_lines)
            
            # Fallback: use first 200 chars
            return response[:200].strip()
            
        except Exception:
            return response[:200].strip() if response else ''
    
    def _generate_final_synthesis(self, total_chunks, endpoint, model, config):
        """
        Generate final synthesis across all chunks
        """
        try:
            synthesis_prompt = f"""
You have analyzed {total_chunks} chunks of security/DFIR data.

Based on the user's question: "{self.prompt}"

Provide a final comprehensive synthesis that:
1. Integrates findings across all chunks
2. Identifies patterns and correlations
3. Prioritizes critical findings
4. Provides actionable recommendations for the investigation

Focus on the most significant security and forensic insights.
"""
            
            response = self._call_ollama(endpoint, model, synthesis_prompt, config)
            
            return {
                'chunk': 'FINAL',
                'event_count': total_chunks,
                'response': response,
                'summary': 'Final synthesis across all analyzed chunks',
                'status': 'success'
            }
            
        except Exception as e:
            return {
                'chunk': 'FINAL',
                'error': str(e),
                'status': 'error'
            }
    
    def _create_result_record(self, result, chunk_id):
        """
        Create Splunk result record from analysis result
        """
        record = OrderedDict()
        record['_time'] = time.time()
        record['llm_chunk'] = str(chunk_id)
        record['llm_status'] = result.get('status', 'unknown')
        record['llm_event_count'] = result.get('event_count', 0)
        record['llm_response'] = result.get('response', result.get('error', 'No response'))
        
        if 'summary' in result:
            record['llm_summary'] = result['summary']
        
        return record


dispatch(LLMHandlerCommand, sys.argv, sys.stdin, sys.stdout, __name__)
