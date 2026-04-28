import socket
import threading
from datetime import datetime
import json
import os
from flask import Flask, render_template, jsonify, send_from_directory
from flask_cors import CORS

# --- CONFIGURATION ---
HOST = '0.0.0.0'
TRAP_PORT = 8888
DASH_PORT = 5001
LOG_FILE = 'logs/threat_intel.json'
MESSAGE = b"Access Denied: You are not authorized to view this resource.\n"

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

# Cache for real-time dashboard updates without reading file every time
intel_logs = []

def load_logs():
    """Loads existing logs from the JSON file."""
    global intel_logs
    if os.path.exists(LOG_FILE):
        try:
            with open(LOG_FILE, "r") as f:
                intel_logs = json.load(f)
        except (json.JSONDecodeError, ValueError):
            intel_logs = []

def save_log(entry):
    """Saves a new log entry to the JSON file and cache."""
    global intel_logs
    intel_logs.append(entry)
    # Keep only last 100 entries for memory
    if len(intel_logs) > 100:
        intel_logs = intel_logs[-100:]
    
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "w") as f:
        json.dump(intel_logs, f, indent=4)

def log_event(ip_address, user_agent=None):
    """Formats and records a connection attempt."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": timestamp,
        "ip": ip_address,
        "ua": user_agent or "TCP Raw Connection",
        "status": "BLOCKED"
    }
    save_log(entry)
    print(f"[*] THREAT DETECTED: {ip_address} at {timestamp}")

# --- THE TRAP (SOCKET LISTENER) ---
def start_trap():
    """Background TCP socket listener to capture any connection (not just HTTP)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, TRAP_PORT))
        server.listen(5)
        print(f"[*] Honeypot Trap active on port {TRAP_PORT}")
        
        while True:
            client, addr = server.accept()
            # Handle the detection
            log_event(addr[0])
            
            # Send the deceptive message
            try:
                client.sendall(MESSAGE)
            except:
                pass
            finally:
                client.close()
    except Exception as e:
        print(f"[!] Trap Error: {e}")
    finally:
        server.close()

# --- THE WEB DASHBOARD (FLASK) ---
@app.route('/')
def dashboard():
    """Serves the main threat intel dashboard."""
    return render_template('index.html')

@app.route('/api/logs')
def get_logs():
    """API endpoint for live dashboard data."""
    return jsonify(intel_logs)

@app.route('/api/stats')
def get_stats():
    """API endpoint for dashboard counters."""
    unique_ips = len(set(log['ip'] for log in intel_logs))
    total_attempts = len(intel_logs)
    return jsonify({
        "total": total_attempts,
        "unique": unique_ips,
        "active_trap": "Online"
    })

if __name__ == "__main__":
    # Pre-load logs
    load_logs()
    
    # Start the TCP Trap in a background thread
    trap_thread = threading.Thread(target=start_trap, daemon=True)
    trap_thread.start()
    
    # Start the Admin Dashboard on port 5000
    print(f"[*] Launching Admin Dashboard at http://localhost:{DASH_PORT}")
    app.run(host=HOST, port=DASH_PORT, debug=False)
