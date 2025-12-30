#!/usr/bin/env python3
import socket
import sys
import threading

def start_server(port, output_file):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(1)
        # print(f"Listening on port {port}...")
        
        try:
            conn, addr = s.accept()
            with conn:
                # print(f"Connected by {addr}")
                with open(output_file, 'wb') as f:
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        f.write(data)
                        f.flush()
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <port> <output_file>", file=sys.stderr)
        sys.exit(1)
    
    start_server(int(sys.argv[1]), sys.argv[2])
