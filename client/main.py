import argparse
from core.client import Client
from ui.terminal_ui import ClientUI
from utils.enums import ClientState
from utils.exceptions import ClientError
from config import (
    DEFAULT_HOST,
    DEFAULT_CLIENT_PORT,
    DEFAULT_SERVER_HOST,
    DEFAULT_SERVER_PORT
)

def main():
    # Add command-line argument parsing
    parser = argparse.ArgumentParser(description='CipherShare Client')
    parser.add_argument('--port', type=int, default=DEFAULT_CLIENT_PORT,
                      help='Port number for this client')
    args = parser.parse_args()

    client = None
    try:
        # Create client instance with port from command-line argument
        client = Client(
            host=DEFAULT_HOST,
            port=args.port,
            server_host=DEFAULT_SERVER_HOST,
            server_port=DEFAULT_SERVER_PORT
        )
        
        if client.start():
            ui = ClientUI(client)
            ui.run()
        else:
            print("Failed to start client")
    except ClientError as e:
        print(f"Client error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    finally:
        if client and client.state == ClientState.ONLINE:
            client.disconnect()

if __name__ == "__main__":
    main()