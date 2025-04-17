import logging
import socket
import threading
from typing import Dict

from utils.enums import MessageType
from models.client_info import ClientInfo
from core.database import DatabaseManager
from core.protocol import Protocol
from handlers.request_handlers import RequestHandler
from utils.logger import logger
from utils.exceptions import ServerError

class Server:
    def __init__(self, host: str, port: int, db_file: str = "server_db.json"):
        self.host = host
        self.port = port
        self.db_manager = DatabaseManager(db_file)
        self.server_socket = None
        self.clients: Dict[str, ClientInfo] = {}  # key: "host:port"
        self.running = False
        self.lock = threading.Lock()

    def start(self):
        """Start the server and listen for incoming connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            logging.info(f"Server started on {self.host}:{self.port}")

            while self.running:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()

        except Exception as e:
            logging.error(f"Server error: {e}")
            self.stop()

    def stop(self):
        """Stop the server and clean up connections."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        
        # Close all client connections
        with self.lock:
            for client_info in self.clients.values():
                try:
                    client_info.socket.close()
                except:
                    pass
            self.clients.clear()
        
        logging.info("Server stopped")

    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle individual client connections and their requests."""
        logging.info(f"New connection from {address}")
        
        try:
            while self.running:
                data = client_socket.recv(1024)
                if not data:
                    break

                msg_type, msg_data = Protocol.parse_message(data)
                response = self._process_message(msg_type, msg_data, client_socket, address)
                client_socket.send(response)

        except Exception as e:
            logging.error(f"Error handling client {address}: {e}")
        finally:
            self._handle_client_disconnect(address)
            client_socket.close()

    def _process_message(self, msg_type: MessageType, msg_data: dict, 
                        client_socket: socket.socket, address: tuple) -> bytes:
        """Process incoming messages and return appropriate responses."""
        try:
            if msg_type == MessageType.CONNECT:
                return self._handle_connect(msg_data, client_socket, address)
            elif msg_type == MessageType.DISCONNECT:
                return self._handle_disconnect(address)
            elif msg_type == MessageType.UPLOAD:
                return self._handle_upload(msg_data, address)
            elif msg_type == MessageType.DOWNLOAD:
                return self._handle_download(msg_data, address)
            elif msg_type == MessageType.LIST_FILES:
                return self._handle_list_files()
            elif msg_type == MessageType.REMOVE_FILE:
                return self._handle_remove_file(msg_data, address)
            else:
                logging.warning(f"Unknown message type: {msg_type}")
                return Protocol.create_message(MessageType.ERROR, 
                    {"message": "Unknown message type"})
        except Exception as e:
            logging.error(f"Error processing message: {e}")
            return Protocol.create_message(MessageType.ERROR, 
                {"message": "Internal server error"})

    def _handle_connect(self, data: dict, client_socket: socket.socket, 
                       address: tuple) -> bytes:
        """Handle client connection requests."""
        host = data["host"]
        port = data["port"]
        files = data.get("files", [])
        client_key = f"{host}:{port}"

        with self.lock:
            if client_key in self.clients:
                # Client reconnecting
                self.clients[client_key].is_online = True
                self.clients[client_key].socket = client_socket
            else:
                # New client
                self.clients[client_key] = ClientInfo(
                    host=host,
                    port=port,
                    socket=client_socket,
                    shared_files=set(files)
                )

            # Update database with client's files
            for file in files:
                self.db_manager.add_file(file, host, port)

        logging.info(f"Client connected: {client_key}")
        return Protocol.create_message(MessageType.SUCCESS, 
            {"message": "Connected successfully"})

    def _handle_disconnect(self, address: tuple) -> bytes:
        """Handle client disconnect requests."""
        client_key = f"{address[0]}:{address[1]}"
        
        with self.lock:
            if client_key in self.clients:
                self.clients[client_key].is_online = False
                logging.info(f"Client disconnected: {client_key}")
                return Protocol.create_message(MessageType.SUCCESS, 
                    {"message": "Disconnected successfully"})
            
        return Protocol.create_message(MessageType.ERROR, 
            {"message": "Client not found"})

    def _handle_upload(self, data: dict, address: tuple) -> bytes:
        """Handle file upload notifications."""
        filename = data["filename"]
        client_key = f"{address[0]}:{address[1]}"

        if client_key not in self.clients or not self.clients[client_key].is_online:
            return Protocol.create_message(MessageType.ERROR, 
                {"message": "Client not connected"})

        self.db_manager.add_file(filename, address[0], address[1])
        self.clients[client_key].shared_files.add(filename)
        
        logging.info(f"File uploaded: {filename} by {client_key}")
        return Protocol.create_message(MessageType.SUCCESS, 
            {"message": "File registered successfully"})

    def _handle_download(self, data: dict, address: tuple) -> bytes:
        """Handle file download requests."""
        filename = data["filename"]
        locations = self.db_manager.get_file_locations(filename)

        # Filter for online clients
        available_locations = [
            loc for loc in locations
            if f"{loc['host']}:{loc['port']}" in self.clients
            and self.clients[f"{loc['host']}:{loc['port']}"].is_online
        ]

        if not available_locations:
            return Protocol.create_message(MessageType.ERROR, 
                {"message": "File not available"})

        # Select first available location
        selected_location = available_locations[0]
        logging.info(f"Download request: {filename} by {address} from {selected_location}")
        
        return Protocol.create_message(MessageType.SUCCESS, {
            "host": selected_location["host"],
            "port": selected_location["port"]
        })

    def _handle_list_files(self) -> bytes:
        """Handle request to list available files."""
        files = self.db_manager.get_all_files()
        return Protocol.create_message(MessageType.SUCCESS, {"files": files})

    def _handle_remove_file(self, data: dict, address: tuple) -> bytes:
        """Handle file removal requests."""
        filename = data["filename"]
        client_key = f"{address[0]}:{address[1]}"

        if client_key not in self.clients:
            return Protocol.create_message(MessageType.ERROR, 
                {"message": "Client not found"})

        if filename not in self.clients[client_key].shared_files:
            return Protocol.create_message(MessageType.ERROR, 
                {"message": "File not owned by client"})

        success = self.db_manager.remove_file(filename, address[0], address[1])
        if success:
            self.clients[client_key].shared_files.remove(filename)
            logging.info(f"File removed: {filename} by {client_key}")
            return Protocol.create_message(MessageType.SUCCESS, 
                {"message": "File removed successfully"})
        
        return Protocol.create_message(MessageType.ERROR, 
            {"message": "Failed to remove file"})

    def _handle_client_disconnect(self, address: tuple):
        """Handle client disconnection cleanup."""
        client_key = f"{address[0]}:{address[1]}"
        
        with self.lock:
            if client_key in self.clients:
                self.clients[client_key].is_online = False
                logging.info(f"Client connection closed: {client_key}")