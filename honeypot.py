import socket
import threading
from datetime import datetime
import os

# Configuration
HOST = '0.0.0.0'
PORT = 8888
LOG_FILE = 'logs/threat_intel.txt'
MESSAGE = b"Access Denied: You are not authorized to view this resource.\n"

def log_event(ip_address):
    """Logs the connection IP and current timestamp to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] Connection Attempt from IP: {ip_address}\n"
    
    # Ensure logs directory exists
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    
    with open(LOG_FILE, "a") as f:
        f.write(log_entry)
    print(f"Logged: {log_entry.strip()}")

def handle_client(client_socket, address):
    """Handles communications with a client in a separate thread."""
    ip_address = address[0]
    print(f"[+] Incoming connection from {ip_address}")
    
    # 1. Log the event
    log_event(ip_address)
    
    # 2. Send 'Access Denied' message
    try:
        client_socket.sendall(MESSAGE)
    except Exception as e:
        print(f"Error sending message to {ip_address}: {e}")
    finally:
        # 3. Close the connection
        client_socket.close()

def start_honeypot():
    """Initializes and starts the honeypot port listener."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
    except PermissionError:
        print(f"Error: Permission denied to bind to port {PORT}. Try a different port or sudo.")
        return
    except OSError as e:
        print(f"Error: Could not bind to {HOST}:{PORT} - {e}")
        return

    server.listen(5)
    print(f"[*] Healthcare Honeypot listening on {HOST}:{PORT}...")
    
    try:
        while True:
            client_socket, address = server.accept()
            # Handle each connection in a new thread
            client_handler = threading.Thread(target=handle_client, args=(client_socket, address))
            client_handler.start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down Healthcare Honeypot...")
    finally:
        server.close()

if __name__ == "__main__":
    start_honeypot()
