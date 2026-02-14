from flask import Flask, render_template, request, jsonify, send_file
import json
import psutil
from shadow_discovery import ShadowDiscovery
from io import BytesIO

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():

    detected = []
    possible = []
    results = {
        "mcp_servers_detected": [],
        "possible_mcp_servers": []
    }

    if request.method == "POST":
        manifest_path = request.form.get("manifest", "config.json")

        scanner = ShadowDiscovery(manifest_path)
        scan_output = scanner.scan_all()
        scanner.export_to_json("shadow_report.json")

        if isinstance(scan_output, dict):
            results = scan_output
            detected = results.get("mcp_servers_detected", [])
            possible = results.get("possible_mcp_servers_detected", [])

    try:
        with open("config.json", "r") as f:
            config_content = f.read()
    except Exception:
        config_content = ""

    return render_template(
        "index.html",
        detected=detected,
        possible=possible,
        results=results,
        config_content=config_content
    )


@app.route("/export", methods=["POST"])
def export():
    data = request.form.get("results")
    buffer = BytesIO()
    buffer.write(data.encode())
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name="mcp_scan_results.json",
        mimetype="application/json"
    )

@app.route("/save_config", methods=["POST"])
def save_config():
    content = request.form.get("config_content")
    with open("config.json", "w") as f:
        f.write(content)
    return "Configuration Saved Successfully"


@app.route("/save_advanced", methods=["POST"])
def save_advanced():
    data = {
        "gemini_key": request.form.get("gemini_key"),
        "claude_key": request.form.get("claude_key"),
        "ollama_key": request.form.get("ollama_key")
    }

    with open("advanced_config.json", "w") as f:
        json.dump(data, f, indent=4)

    return "Advanced Configuration Saved"

if __name__ == "__main__":
    app.run(debug=True)
    
