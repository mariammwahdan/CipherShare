#!/usr/bin/env python3
"""
CipherShare: A Secure Distributed File Sharing Platform
Main script - Used to start either client or server mode

Usage:
  python main.py client [server_host] [server_port]
  python main.py server [host] [port]
"""

import sys
import os
import time

def print_banner():
    """Print the CipherShare banner"""
    banner = """
  _____  _         _                 _____  _                        
 / ____|(_)       | |               / ____|| |                       
| |      _  _ __  | |__    ___  _ _| (___  | |__    __ _  _ __  ___ 
| |     | || '_ \ | '_ \  / _ \| '__\___ \ | '_ \  / _` || '__|/ _ \\
| |____ | || |_) || | | ||  __/| |  ____) || | | || (_| || |  |  __/
 \_____||_|| .__/ |_| |_| \___||_| |_____/ |_| |_| \__,_||_|   \___|
           | |                                                       
           |_|                  Secure Distributed File Sharing
    """
    print(banner)
    print("Phase 1 & 2 Implementation - P2P File Sharing with Authentication")
    print("=" * 70)


def show_usage():
    """Show usage information"""
    print("\nUsage:")
    print("  python main.py client [server_host] [server_port]")
    print("  python main.py server [host] [port]")
    print("\nExamples:")
    print("  python main.py client localhost 5555")
    print("  python main.py server 0.0.0.0 5555")


def start_client(server_host='localhost', server_port=5555):
    """Start the CipherShare client"""
    # This is a delayed import to avoid circular imports
    from client_ui import CipherShareClientUI
    
    print(f"Starting CipherShare Client - connecting to {server_host}:{server_port}")
    time.sleep(1)  # Short pause for better UX
    
    # Create and run the client UI
    client_ui = CipherShareClientUI(server_host, server_port)
    client_ui.run()


def start_server(host='0.0.0.0', port=5555):
    """Start the CipherShare server"""
    # This is a delayed import to avoid circular imports
    from server import CipherShareServer
    
    print(f"Starting CipherShare Server on {host}:{port}")
    print("Press Ctrl+C to stop the server")
    time.sleep(1)  # Short pause for better UX
    
    # Create and start the server
    server = CipherShareServer(host, port)
    server.start()


def main():
    """Main function to parse arguments and start client or server"""
    print_banner()
    
    if len(sys.argv) < 2:
        show_usage()
        return
    
    mode = sys.argv[1].lower()
    
    if mode == 'client':
        # Default values
        server_host = 'localhost'
        server_port = 5555
        
        # Parse optional arguments
        if len(sys.argv) > 2:
            server_host = sys.argv[2]
        if len(sys.argv) > 3:
            try:
                server_port = int(sys.argv[3])
            except ValueError:
                print(f"Error: Invalid port number '{sys.argv[3]}'")
                return
        
        start_client(server_host, server_port)
    
    elif mode == 'server':
        # Default values
        host = '0.0.0.0'
        port = 5555
        
        # Parse optional arguments
        if len(sys.argv) > 2:
            host = sys.argv[2]
        if len(sys.argv) > 3:
            try:
                port = int(sys.argv[3])
            except ValueError:
                print(f"Error: Invalid port number '{sys.argv[3]}'")
                return
        
        start_server(host, port)
    
    else:
        print(f"Error: Unknown mode '{mode}'")
        show_usage()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting CipherShare...")
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)