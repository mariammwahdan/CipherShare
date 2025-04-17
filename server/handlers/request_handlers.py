# server/handlers/request_handlers.py

import socket
import threading
from typing import Dict, Tuple, Optional
from models.client_info import ClientInfo
from core.protocol import Protocol
from utils.enums import MessageType
from utils.logger import logger
from utils.exceptions import ClientHandlingError
from config import BUFFER_SIZE

class RequestHandler:
    def __init__(self, server):
        """
        Initialize the RequestHandler with a reference to the server instance.
        
        Args:
            server: The main server instance
        """
        self.server = server

    def handle_request(self, msg_type: MessageType, msg_data: dict, 
                      client_socket: socket.socket, address: tuple) -> bytes:
        """
        Main request handler that routes requests to specific handlers.
        
        Args:
            msg_type: Type of the message received
            msg_data: Data contained in the message
            client_socket: Socket connection to the client
            address: Client's address tuple (host, port)
            
        Returns:
            bytes: Response message to be sent to the client
        """
        try:
            handlers = {
                MessageType.CONNECT: self.handle_connect,
                MessageType.DISCONNECT: self.handle_disconnect,
                MessageType.UPLOAD: self.handle_upload,
                MessageType.DOWNLOAD: self.handle_download,
                MessageType.LIST_FILES: self.handle_list_files,
                MessageType.REMOVE_FILE: self.handle_remove_file
            }
            
            handler = handlers.get(msg_type)
            if handler:
                return handler(msg_data, client_socket, address)
            else:
                logger.warning(f"Unknown message type: {msg_type}")
                return Protocol.create_message(
                    MessageType.ERROR, 
                    {"message": "Unknown request type"}
                )
                
        except Exception as e:
            logger.error(f"Error handling request: {e}")
            return Protocol.create_message(
                MessageType.ERROR, 
                {"message": "Internal server error"}
            )

    def handle_connect(self, data: dict, client_socket: socket.socket, 
                    address: tuple) -> bytes:
        """Handle client connection requests."""
        try:
            host = data.get("host", address[0])
            port = data.get("port", address[1])
            files = data.get("files", [])
            client_key = f"{host}:{port}"

            with self.server.lock:
                if client_key in self.server.clients:
                    # Client reconnecting
                    self.server.clients[client_key].is_online = True
                    self.server.clients[client_key].socket = client_socket
                    logger.info(f"Client reconnected: {client_key}")
                else:
                    # New client
                    self.server.clients[client_key] = ClientInfo(
                        host=host,
                        port=port,
                        socket=client_socket
                    )
                    logger.info(f"New client connected: {client_key}")

                # Update shared files
                self.server.clients[client_key].shared_files.update(files)
                for file in files:
                    self.server.db_manager.add_file(file, host, port)

            return Protocol.create_message(MessageType.SUCCESS, 
                {"message": "Connected successfully"})
                
        except Exception as e:
            logger.error(f"Error handling connect request: {e}")
            return Protocol.create_message(MessageType.ERROR, 
                {"message": str(e)})

    def handle_upload(self, data: dict, client_socket: socket.socket, 
                    address: tuple) -> bytes:
        """Handle file upload notifications."""
        try:
            filename = data["filename"]
            host = data.get("host", address[0])
            port = data.get("port", address[1])
            client_key = f"{host}:{port}"

            with self.server.lock:
                if client_key not in self.server.clients:
                    return Protocol.create_message(MessageType.ERROR, 
                        {"message": "Client not connected"})
                        
                if not self.server.clients[client_key].is_online:
                    return Protocol.create_message(MessageType.ERROR, 
                        {"message": "Client is offline"})

                self.server.db_manager.add_file(filename, host, port)
                self.server.clients[client_key].shared_files.add(filename)
                
                logger.info(f"File uploaded: {filename} by {client_key}")
                return Protocol.create_message(MessageType.SUCCESS, 
                    {"message": "File registered successfully"})
                    
        except Exception as e:
            logger.error(f"Error handling upload request: {e}")
            return Protocol.create_message(MessageType.ERROR, 
                {"message": str(e)})

    def handle_disconnect(self, data: dict, client_socket: socket.socket, 
                        address: tuple) -> bytes:
        """
        Handle client disconnect requests.
        
        Args:
            data: Disconnect request data
            client_socket: Client's socket connection
            address: Client's address tuple
            
        Returns:
            bytes: Response message
        """
        try:
            client_key = f"{address[0]}:{address[1]}"
            
            with self.server.lock:
                if client_key in self.server.clients:
                    self.server.clients[client_key].is_online = False
                    logger.info(f"Client disconnected: {client_key}")
                    return Protocol.create_message(
                        MessageType.SUCCESS, 
                        {"message": "Disconnected successfully"}
                    )
                
            return Protocol.create_message(
                MessageType.ERROR, 
                {"message": "Client not found"}
            )
            
        except Exception as e:
            raise ClientHandlingError(f"Error handling disconnect request: {e}")

    # def handle_upload(self, data: dict, client_socket: socket.socket, 
    #                  address: tuple) -> bytes:
    #     """
    #     Handle file upload notifications.
        
    #     Args:
    #         data: Upload request data including filename
    #         client_socket: Client's socket connection
    #         address: Client's address tuple
            
    #     Returns:
    #         bytes: Response message
    #     """
    #     try:
    #         filename = data["filename"]
    #         client_key = f"{address[0]}:{address[1]}"

    #         if client_key not in self.server.clients or \
    #            not self.server.clients[client_key].is_online:
    #             return Protocol.create_message(
    #                 MessageType.ERROR, 
    #                 {"message": "Client not connected"}
    #             )

    #         with self.server.lock:
    #             self.server.db_manager.add_file(filename, address[0], address[1])
    #             self.server.clients[client_key].shared_files.add(filename)
                
    #         logger.info(f"File uploaded: {filename} by {client_key}")
    #         return Protocol.create_message(
    #             MessageType.SUCCESS, 
    #             {"message": "File registered successfully"}
    #         )
            
    #     except Exception as e:
    #         raise ClientHandlingError(f"Error handling upload request: {e}")

    def handle_download(self, data: dict, client_socket: socket.socket, 
                       address: tuple) -> bytes:
        """
        Handle file download requests.
        
        Args:
            data: Download request data including filename
            client_socket: Client's socket connection
            address: Client's address tuple
            
        Returns:
            bytes: Response message with file location
        """
        try:
            filename = data["filename"]
            locations = self.server.db_manager.get_file_locations(filename)

            # Filter for online clients
            available_locations = [
                loc for loc in locations
                if f"{loc['host']}:{loc['port']}" in self.server.clients
                and self.server.clients[f"{loc['host']}:{loc['port']}"].is_online
            ]

            if not available_locations:
                return Protocol.create_message(
                    MessageType.ERROR, 
                    {"message": "File not available"}
                )

            # Select first available location
            selected_location = available_locations[0]
            logger.info(
                f"Download request: {filename} by {address} "
                f"from {selected_location}"
            )
            
            return Protocol.create_message(
                MessageType.SUCCESS, 
                {
                    "host": selected_location["host"],
                    "port": selected_location["port"]
                }
            )
            
        except Exception as e:
            raise ClientHandlingError(f"Error handling download request: {e}")

    def handle_list_files(self, data: dict, client_socket: socket.socket, 
                         address: tuple) -> bytes:
        """
        Handle request to list available files.
        
        Args:
            data: List files request data
            client_socket: Client's socket connection
            address: Client's address tuple
            
        Returns:
            bytes: Response message with list of files
        """
        try:
            files = self.server.db_manager.get_all_files()
            return Protocol.create_message(
                MessageType.SUCCESS, 
                {"files": files}
            )
            
        except Exception as e:
            raise ClientHandlingError(f"Error handling list files request: {e}")

    def handle_remove_file(self, data: dict, client_socket: socket.socket, 
                          address: tuple) -> bytes:
        """
        Handle file removal requests.
        
        Args:
            data: Remove file request data including filename
            client_socket: Client's socket connection
            address: Client's address tuple
            
        Returns:
            bytes: Response message
        """
        try:
            filename = data["filename"]
            client_key = f"{address[0]}:{address[1]}"

            if client_key not in self.server.clients:
                return Protocol.create_message(
                    MessageType.ERROR, 
                    {"message": "Client not found"}
                )

            if filename not in self.server.clients[client_key].shared_files:
                return Protocol.create_message(
                    MessageType.ERROR, 
                    {"message": "File not owned by client"}
                )

            with self.server.lock:
                success = self.server.db_manager.remove_file(
                    filename, 
                    address[0], 
                    address[1]
                )
                if success:
                    self.server.clients[client_key].shared_files.remove(filename)
                    logger.info(f"File removed: {filename} by {client_key}")
                    return Protocol.create_message(
                        MessageType.SUCCESS, 
                        {"message": "File removed successfully"}
                    )
            
            return Protocol.create_message(
                MessageType.ERROR, 
                {"message": "Failed to remove file"}
            )
            
        except Exception as e:
            raise ClientHandlingError(f"Error handling remove file request: {e}")

    def handle_client_disconnect(self, address: tuple):
        """
        Handle cleanup when a client disconnects.
        
        Args:
            address: Client's address tuple
        """
        try:
            client_key = f"{address[0]}:{address[1]}"
            
            with self.server.lock:
                if client_key in self.server.clients:
                    self.server.clients[client_key].is_online = False
                    logger.info(f"Client connection closed: {client_key}")
                    
        except Exception as e:
            logger.error(f"Error handling client disconnect: {e}")