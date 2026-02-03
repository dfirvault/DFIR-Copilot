# DFIR Copilot
A Splunk app that brings local, offline LLM-powered analysis directly to your DFIR and threat hunting workflows. DFIR Copilot uses Ollama to run models like Mistral or Llama3 locally, enabling you to ask complex questions about your Splunk search results without ever sending data to the cloud.

## App Overview 
DFIR Copilot by DFIRVault transforms how cybersecurity analysts interact with Splunk data. By implementing a sophisticated Retrieval-Augmented Generation (RAG) pipeline with progressive summarization, the app allows you to converse with your logs. It maintains context across large datasets, providing coherent, detailed analyses for incident response, forensic investigations, and threat hunting—all processed securely on your local infrastructure.

## Core Features & Benefits
- 💸 100% Free: No cost to setup and get running in your lab, just connect to your existing splunk trial or enterprise server.

- 🔒 100% Local & Private: Works completely offline with Ollama. Your sensitive log data never leaves your network.

- 🧠 DFIR-Optimized AI: Built specifically for cybersecurity with analysis modes for forensics, threat intelligence, summarization, and detailed investigation.

- 🔄 Advanced RAG Pipeline: Employs intelligent chunking and progressive summarization to prevent context loss, even when analyzing thousands of events.

- ⚙️ Easy Configuration: User-friendly, web-based setup to connect to your Ollama instance and configure analysis parameters.

- 🚀 Production-Ready: Follows Splunk development best practices for reliability and seamless integration into your existing workflows.

## How It Works
- Search: Run a standard Splunk search to filter your events.

- Analyze: Pipe the results to the custom llmhandler command with your analysis prompt.

- Get Insights: The app chunks the data, sends it to your local LLM with carried-over context, and returns a structured analysis directly in your Splunk results.

## Use Cases
- Incident Triage: Get an immediate AI-summarized overview of security alerts.

- Forensic Timeline Reconstruction: Have the LLM analyze Windows event logs to build a narrative of an attack.

- Threat Hunting: Identify complex patterns like C2 beaconing or data exfiltration in proxy or DNS logs.

- Log Analysis: Understand noisy or complex application logs without writing intricate SPL.
