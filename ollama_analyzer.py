# ollama_analyzer.py

import json
import requests


OLLAMA_API_URL = "https://api.ollama.com/v1/chat/completions"
DEFAULT_MODEL = "llama3.1:8b"


def analyze_mcp_security(api_key, server_info, tools_data):
    """
    Sends MCP server + tool data to Ollama Cloud.
    Returns LLM security analysis (text).
    """

    if not api_key:
        return "Ollama Cloud API key not configured."

    try:
        prompt = f"""
You are a senior cybersecurity analyst.

Analyze the following MCP server and its exposed tools.

Server Info:
{json.dumps(server_info, indent=2)}

Tools:
{json.dumps(tools_data, indent=2)}

Return output strictly in JSON format:

{{
  "risk_level": "Low | Medium | High | Critical",
  "reason": "...",
  "abuse_scenarios": "...",
  "mitigations": "..."
}}
"""

        payload = {
            "model": DEFAULT_MODEL,
            "messages": [
                {"role": "system", "content": "You are a senior security analyst."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        response = requests.post(
            OLLAMA_API_URL,
            headers=headers,
            json=payload,
            timeout=30
        )

        response.raise_for_status()
        data = response.json()

        return data["choices"][0]["message"]["content"]

    except Exception as e:
        return f"Ollama analysis failed: {str(e)}"
