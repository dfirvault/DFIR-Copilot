#!/usr/bin/env python3
"""
DFIR Copilot by DFIRVault Configuration REST Handler
Manages LLM configuration through Splunk REST API
"""

import os
import sys
import json
import requests
import splunk.admin as admin
import splunk.entity as entity


class DFIRVaultConfigHandler(admin.MConfigHandler):
    """
    REST handler for DFIRVault Copilot configuration management
    """
    
    def setup(self):
        """
        Set up supported arguments for the REST endpoint
        """
        if self.requestedAction == admin.ACTION_EDIT or self.requestedAction == admin.ACTION_CREATE:
            # Configuration parameters
            self.supportedArgs.addReqArg('endpoint')
            self.supportedArgs.addReqArg('model')
            self.supportedArgs.addOptArg('temperature')
            self.supportedArgs.addOptArg('max_tokens')
            self.supportedArgs.addOptArg('timeout')
            self.supportedArgs.addOptArg('chunk_size')
            self.supportedArgs.addOptArg('max_context_events')
            self.supportedArgs.addOptArg('overlap_events')
            self.supportedArgs.addOptArg('analysis_mode')
            self.supportedArgs.addOptArg('system_prompt')
    
    def handleList(self, confInfo):
        """
        Handle GET requests - return current configuration
        """
        try:
            # Read configuration from file
            config = self._read_config()
            
            # Also fetch available models from Ollama
            available_models = self._fetch_available_models(config.get('endpoint', 'http://localhost:11434'))
            
            # Add configuration to response
            confItem = confInfo['llm_config']
            for key, value in config.items():
                confItem[key] = value
            
            # Add available models as JSON string
            confItem['available_models'] = json.dumps(available_models)
            
        except Exception as e:
            raise admin.InternalException(f"Error reading configuration: {str(e)}")
    
    def handleEdit(self, confInfo):
        """
        Handle POST requests - update configuration
        """
        try:
            # Get the new configuration values
            name = self.callerArgs.id
            args = self.callerArgs.data
            
            # Validate endpoint connectivity
            endpoint = args.get('endpoint', [''])[0]
            if endpoint:
                if not self._test_ollama_connection(endpoint):
                    raise admin.BadRequestException(f"Cannot connect to Ollama at {endpoint}")
            
            # Write configuration to file
            self._write_config(args)
            
            # Mark app as configured
            self._mark_configured()
            
        except Exception as e:
            raise admin.InternalException(f"Error updating configuration: {str(e)}")
    
    def handleCreate(self, confInfo):
        """
        Handle initial configuration creation
        """
        self.handleEdit(confInfo)
    
    def _read_config(self):
        """
        Read configuration from dfirvault.conf
        """
        config = {}
        
        try:
            app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            config_paths = [
                os.path.join(app_root, 'local', 'dfirvault.conf'),
                os.path.join(app_root, 'default', 'dfirvault.conf')
            ]
            
            for config_path in config_paths:
                if os.path.exists(config_path):
                    with open(config_path, 'r') as f:
                        current_section = None
                        for line in f:
                            line = line.strip()
                            if line.startswith('['):
                                current_section = line.strip('[]')
                            elif line and not line.startswith('#') and '=' in line:
                                key, value = line.split('=', 1)
                                config[key.strip()] = value.strip()
                    break
        except Exception as e:
            # Return defaults if config can't be read
            config = {
                'endpoint': 'http://localhost:11434',
                'model': 'mistral',
                'temperature': '0.7',
                'max_tokens': '2000',
                'timeout': '120',
                'chunk_size': '10',
                'max_context_events': '100',
                'overlap_events': '2',
                'analysis_mode': 'forensic',
                'system_prompt': 'You are a cybersecurity and DFIR expert assistant.'
            }
        
        return config
    
    def _write_config(self, args):
        """
        Write configuration to local/dfirvault.conf
        """
        try:
            app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            local_dir = os.path.join(app_root, 'local')
            config_path = os.path.join(local_dir, 'dfirvault.conf')
            
            # Ensure local directory exists
            if not os.path.exists(local_dir):
                os.makedirs(local_dir, mode=0o755)
            
            # Build configuration content
            config_lines = ['[llm_config]\n']
            
            # Define configuration keys and their defaults
            config_keys = {
                'endpoint': 'http://localhost:11434',
                'model': 'mistral',
                'temperature': '0.7',
                'max_tokens': '2000',
                'timeout': '120',
                'chunk_size': '10',
                'max_context_events': '100',
                'overlap_events': '2',
                'analysis_mode': 'forensic',
                'system_prompt': 'You are a cybersecurity and DFIR expert assistant.'
            }
            
            # Write each configuration value
            for key, default_value in config_keys.items():
                value = args.get(key, [default_value])[0] if key in args else default_value
                config_lines.append(f"{key} = {value}\n")
            
            # Write to file
            with open(config_path, 'w') as f:
                f.writelines(config_lines)
            
            # Set appropriate permissions
            os.chmod(config_path, 0o644)
            
        except Exception as e:
            raise Exception(f"Failed to write configuration: {str(e)}")
    
    def _test_ollama_connection(self, endpoint):
        """
        Test connection to Ollama endpoint
        """
        try:
            url = f"{endpoint}/api/tags"
            response = requests.get(url, timeout=5)
            return response.status_code == 200
        except Exception:
            return False
    
    def _fetch_available_models(self, endpoint):
        """
        Fetch available models from Ollama
        """
        try:
            url = f"{endpoint}/api/tags"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                models = data.get('models', [])
                return [model.get('name', 'unknown') for model in models]
            else:
                return []
        except Exception:
            return []
    
    def _mark_configured(self):
        """
        Mark the app as configured in app.conf
        """
        try:
            app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            local_dir = os.path.join(app_root, 'local')
            app_conf_path = os.path.join(local_dir, 'app.conf')
            
            # Ensure local directory exists
            if not os.path.exists(local_dir):
                os.makedirs(local_dir, mode=0o755)
            
            # Write minimal app.conf to mark as configured
            with open(app_conf_path, 'w') as f:
                f.write('[install]\n')
                f.write('is_configured = true\n')
            
            os.chmod(app_conf_path, 0o644)
            
        except Exception as e:
            # Non-critical error
            pass


# Initialize the handler
admin.init(DFIRVaultConfigHandler, admin.CONTEXT_APP_AND_USER)
