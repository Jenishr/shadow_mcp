import os
import json
import platform
import psutil
from pathlib import Path
from typing import Dict, Any
import tomllib as toml


class ShadowDiscovery:

    def __init__(self, configpath: str):
        with open(configpath, 'r') as f:
            self.manifest = json.load(f)

        self.current_os = self.getplatformkey()
        self.results = {
            "mcp_servers_detected": [],
            "possible_mcp_servers_detected": []
        }

    def getplatformkey(self) -> str:
        sys_name = platform.system().lower()
        if sys_name == "darwin": return "darwin"
        if sys_name == "linux": return "linux"
        if sys_name == "windows": return "win32"
        return "unknown"

    def scan_all(self):
        if self.current_os == "unknown":
            print("Unsupported platform.")
            return self.results

        self.scan_configs()
        self.scan_procs()

        return self.results

    def scan_configs(self):
        platform_data = self.manifest["platforms"].get(self.current_os, {})
        clients = platform_data.get("clients", [])

        for client in clients:
            client_name = client["name"]

            for path_str in client.get("config_paths", []):
                full_path = Path(os.path.expandvars(os.path.expanduser(path_str)))

                if full_path.exists():
                    self._parse_mcp_config(full_path, client_name)

    def _parse_mcp_config(self, path: Path, client_name: str):
        try:
            if not path.exists():
                return

            with open(path, "rb") as f:
                data = toml.load(f)

            if not isinstance(data, dict):
                return

            value = data.get("mcp_servers")
            if not value:
                return

            # Handle [[mcp_servers]] (list)
            if isinstance(value, list):
                for item in value:
                    if not isinstance(item, dict):
                        continue
                    self._store_confirmed_server(item, path, client_name)

            # Handle [mcp_servers.name] (dict)
            elif isinstance(value, dict):
                for name, item in value.items():
                    if isinstance(item, dict):
                        item["name"] = name
                        self._store_confirmed_server(item, path, client_name)

        except Exception as e:
            print(f"Error parsing {path}: {e}")

    def _store_confirmed_server(self, server: Dict[str, Any], path: Path, client_name: str):

        server_type = "http" if server.get("url") else "stdio"

        self.results["mcp_servers_detected"].append({
            "client": client_name,
            "source": "Config",
            "server_id": server.get("name"),
            "type": server_type,
            "command": server.get("command"),
            "args": server.get("args", []),
            "url": server.get("url"),
            "env": server.get("env", {}),
            "config_path": str(path)
        })

    def scan_procs(self):

        keywords = ["mcp", "modelcontextprotocol", "npx", "uvx"]

        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cmd = proc.info['cmdline']
                if not cmd:
                    continue

                cmd_str = " ".join(cmd).lower()

                if any(k in cmd_str for k in keywords):

                    ports = self.get_process_ports(proc)

                    self.results["possible_mcp_servers_detected"].append({
                        "pid": proc.info['pid'],
                        "source": "Process",
                        "process_name": proc.info['name'],
                        "command": cmd[0],
                        "args": cmd[1:],
                        "listening_ports": ports
                    })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def get_process_ports(self, proc):
        ports = []

        try:
            connections = proc.connections(kind='inet')
            for conn in connections:
                if conn.status == psutil.CONN_LISTEN:
                    ports.append(conn.laddr.port)
        except Exception:
            pass

        return ports

    def export_to_json(self, output_path="shadow_mcp_report.json"):
        with open(output_path, "w") as f:
            json.dump(self.results, f, indent=4)
        print(f"Report exported to {output_path}")


# scanner = ShadowDiscovery("config.json")
# results = scanner.scan_all()
# print(json.dumps(results, indent=4))
# scanner.export_to_json("shadow_report.json")