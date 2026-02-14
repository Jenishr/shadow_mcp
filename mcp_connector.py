import requests


def fetch_http_tools(base_url):
    """
    Fetch tools from an HTTP MCP server using JSON-RPC.
    Returns JSON response or {"error": "..."}.
    """

    try:
        response = requests.post(
            f"{base_url}/tools/list",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/list"
            },
            timeout=10
        )

        response.raise_for_status()
        return response.json()

    except Exception as e:
        return {"error": str(e)}
