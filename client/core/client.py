import socket
import threading
import os
from typing import List, Optional

from utils.enums import MessageType, ClientState
from utils.exceptions import ConnectionError, FileTransferError
from .protocol import Protocol
from .file_manager import FileManager
from config import BUFFER_SIZE

import socket
import threading
import os
from typing import List, Optional

from utils.enums import MessageType, ClientState
from utils.exceptions import ConnectionError, FileTransferError
from .protocol import Protocol
from .file_manager import FileManager
from config import BUFFER_SIZE

import os
import socket
import threading
import shutil
from typing import List, Optional
from utils.enums import MessageType, ClientState
from utils.exceptions import ClientError
from .protocol import Protocol
from .file_manager import FileManager

class Client:
    def __init__(self, host: str, port: int, server_host: str, server_port: int):
        self.host = host
        self.port = port
        self.server_host = server_host
        self.server_port = server_port
        self.state = ClientState.OFFLINE
        
        # Create necessary directories
        os.makedirs('shared_files', exist_ok=True)
        os.makedirs('downloads', exist_ok=True)
        
        self.file_manager = FileManager("shared_files.txt")
        self.server_socket = None
        self.listen_socket = None
        self.listen_thread = None
        self.transfer_threads = []

    def _connect_to_server(self):
        try:
            message = Protocol.create_message(
                MessageType.CONNECT,
                {
                    "host": self.host,
                    "port": self.port,
                    "files": self.file_manager.shared_files
                }
            )
            self.server_socket.send(message)
            response = self.server_socket.recv(1024)
            msg_type, data = Protocol.parse_message(response)
            
            if msg_type == MessageType.SUCCESS:
                self.state = ClientState.ONLINE
                print("Successfully connected to server")
                return True
            else:
                print(f"Failed to connect to server: {data.get('message', 'Unknown error')}")
                return False
        except Exception as e:
            print(f"Error connecting to server: {e}")
            return False

    def start(self):
        try:
            # Connect to server
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((self.server_host, self.server_port))
            print(f"Connected to server at {self.server_host}:{self.server_port}")

            # Start listening for incoming connections
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.bind((self.host, self.port))
            self.listen_socket.listen(5)
            print(f"Listening for incoming connections on {self.host}:{self.port}")

            # Start listener thread
            self.listen_thread = threading.Thread(target=self._listen_for_connections)
            self.listen_thread.daemon = True
            self.listen_thread.start()

            # Connect to server with protocol
            if self._connect_to_server():
                return True
            else:
                self.stop()
                return False
        except Exception as e:
            print(f"Error starting client: {e}")
            self.stop()
            return False

    def stop(self):
        try:
            if self.server_socket:
                self.server_socket.close()
            if self.listen_socket:
                self.listen_socket.close()
            self.state = ClientState.OFFLINE
        except Exception as e:
            print(f"Error stopping client: {e}")

    def upload_file(self, filename: str) -> bool:
        if self.state != ClientState.ONLINE:
            print("Error: Client is not connected to server")
            return False

        try:
            # Normalize file path
            filename = os.path.normpath(filename)
            
            # Check if file exists
            if not os.path.exists(filename):
                print(f"Error: File {filename} does not exist")
                return False

            # Get just the filename without path
            base_filename = os.path.basename(filename)
            
            # Copy file to shared directory
            shared_file_path = os.path.join('shared_files', base_filename)
            shutil.copy2(filename, shared_file_path)

            # Notify server about the new file
            message = Protocol.create_message(
                MessageType.UPLOAD,
                {
                    "filename": base_filename,
                    "host": self.host,
                    "port": self.port
                }
            )
            
            print(f"Sending upload request to server for {base_filename}")
            self.server_socket.send(message)
            
            # Wait for server response
            response = self.server_socket.recv(1024)
            msg_type, data = Protocol.parse_message(response)

            if msg_type == MessageType.SUCCESS:
                self.file_manager.add_file(base_filename)
                print(f"Successfully uploaded {base_filename}")
                return True
            else:
                print(f"Server rejected upload: {data.get('message', 'Unknown error')}")
                return False

        except Exception as e:
            print(f"Error during upload: {e}")
            self.state = ClientState.OFFLINE  # Mark as offline if connection is lost
            return False

    # def upload_file(self, filename: str) -> bool:
    #     try:
    #         # Normalize file path
    #         filename = os.path.normpath(filename)
            
    #         # Check if file exists
    #         if not os.path.exists(filename):
    #             print(f"Error: File {filename} does not exist")
    #             return False

    #         # Get just the filename without path
    #         base_filename = os.path.basename(filename)
            
    #         # Copy file to shared directory
    #         shared_file_path = os.path.join('shared_files', base_filename)
    #         shutil.copy2(filename, shared_file_path)

    #         # Notify server about the new file
    #         message = Protocol.create_message(
    #             MessageType.UPLOAD,
    #             {
    #                 "filename": base_filename,
    #                 "host": self.host,
    #                 "port": self.port
    #             }
    #         )
            
    #         print(f"Sending upload request to server for {base_filename}")
    #         self.server_socket.send(message)
            
    #         # Wait for server response
    #         response = self.server_socket.recv(1024)
    #         msg_type, data = Protocol.parse_message(response)

    #         if msg_type == MessageType.SUCCESS:
    #             self.file_manager.add_file(base_filename)
    #             print(f"Successfully uploaded {base_filename}")
    #             return True
    #         else:
    #             print(f"Server rejected upload: {data.get('message', 'Unknown error')}")
    #             return False

    #     except Exception as e:
    #         print(f"Error during upload: {e}")
    #         return False

    def _listen_for_connections(self):
        while True:
            try:
                client_socket, address = self.listen_socket.accept()
                transfer_thread = threading.Thread(
                    target=self._handle_incoming_transfer,
                    args=(client_socket,)
                )
                transfer_thread.daemon = True
                transfer_thread.start()
                self.transfer_threads.append(transfer_thread)
            except Exception as e:
                print(f"Error in listener: {e}")
                break

    def _handle_incoming_transfer(self, client_socket):
        try:
            data = client_socket.recv(1024)
            msg_type, msg_data = Protocol.parse_message(data)
            
            if msg_type == MessageType.FILE_TRANSFER:
                filename = msg_data["filename"]
                file_path = os.path.join('shared_files', filename)
                
                if os.path.exists(file_path):
                    with open(file_path, 'rb') as f:
                        while True:
                            data = f.read(1024)
                            if not data:
                                break
                            client_socket.send(data)
                    print(f"File {filename} sent successfully")
                else:
                    print(f"File {filename} not found in shared directory")
        except Exception as e:
            print(f"Error handling incoming transfer: {e}")
        finally:
            client_socket.close()

    # def start(self):
    #     try:
    #         # Connect to server
    #         self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         self.server_socket.connect((self.server_host, self.server_port))
    #         print(f"Connected to server at {self.server_host}:{self.server_port}")

    #         # Start listening for incoming connections
    #         self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         self.listen_socket.bind((self.host, self.port))
    #         self.listen_socket.listen(5)
    #         print(f"Listening for incoming connections on {self.host}:{self.port}")

    #         # Start listener thread
    #         self.listen_thread = threading.Thread(target=self._listen_for_connections)
    #         self.listen_thread.daemon = True
    #         self.listen_thread.start()

    #         # Connect to server
    #         self._connect_to_server()
    #         return True
    #     except Exception as e:
    #         print(f"Error starting client: {e}")
    #         return False

    # def start(self):
    #     try:
    #         # Connect to server
    #         self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         self.server_socket.connect((self.server_host, self.server_port))

    #         # Start listening for incoming connections
    #         self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #         self.listen_socket.bind((self.host, self.port))
    #         self.listen_socket.listen(5)

    #         # Start listener thread
    #         self.listen_thread = threading.Thread(target=self._listen_for_connections)
    #         self.listen_thread.daemon = True
    #         self.listen_thread.start()

    #         # Connect to server
    #         self._connect_to_server()
    #         return True
    #     except Exception as e:
    #         print(f"Error starting client: {e}")
    #         return False

    # def _connect_to_server(self):
    #     message = Protocol.create_message(
    #         MessageType.CONNECT,
    #         {
    #             "host": self.host,
    #             "port": self.port,
    #             "files": self.file_manager.shared_files
    #         }
    #     )
    #     self.server_socket.send(message)
    #     response = self.server_socket.recv(1024)
    #     msg_type, data = Protocol.parse_message(response)
        
    #     if msg_type == MessageType.SUCCESS:
    #         self.state = ClientState.ONLINE
    #         print("Successfully connected to server")
    #     else:
    #         raise Exception("Failed to connect to server")

    # def _listen_for_connections(self):
    #     while True:
    #         try:
    #             client_socket, address = self.listen_socket.accept()
    #             transfer_thread = threading.Thread(
    #                 target=self._handle_incoming_transfer,
    #                 args=(client_socket,)
    #             )
    #             transfer_thread.daemon = True
    #             transfer_thread.start()
    #             self.transfer_threads.append(transfer_thread)
    #         except Exception as e:
    #             print(f"Error in listener: {e}")

    # def _handle_incoming_transfer(self, client_socket):
    #     try:
    #         data = client_socket.recv(1024)
    #         msg_type, msg_data = Protocol.parse_message(data)
            
    #         if msg_type == MessageType.FILE_TRANSFER:
    #             filename = msg_data["filename"]
    #             if filename in self.file_manager.shared_files:
    #                 self._send_file(client_socket, filename)
    #     except Exception as e:
    #         print(f"Error handling transfer: {e}")
    #     finally:
    #         client_socket.close()

    def _send_file(self, client_socket, filename):
        try:
            with open(filename, 'rb') as f:
                while True:
                    data = f.read(1024)
                    if not data:
                        break
                    client_socket.send(data)
        except Exception as e:
            print(f"Error sending file: {e}")

    # def upload_file(self, filename: str) -> bool:
    #     if not os.path.exists(filename):
    #         print("File does not exist")
    #         return False

    #     message = Protocol.create_message(
    #         MessageType.UPLOAD,
    #         {"filename": filename}
    #     )
    #     self.server_socket.send(message)
    #     response = self.server_socket.recv(1024)
    #     msg_type, data = Protocol.parse_message(response)

    #     if msg_type == MessageType.SUCCESS:
    #         self.file_manager.add_file(filename)
    #         return True
    #     return False

    def download_file(self, filename: str) -> bool:
        message = Protocol.create_message(
            MessageType.DOWNLOAD,
            {"filename": filename}
        )
        self.server_socket.send(message)
        response = self.server_socket.recv(1024)
        msg_type, data = Protocol.parse_message(response)

        if msg_type == MessageType.SUCCESS:
            return self._download_from_peer(filename, data["host"], data["port"])
        return False

    def _download_from_peer(self, filename: str, host: str, port: int) -> bool:
        try:
            peer_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            peer_socket.connect((host, port))

            message = Protocol.create_message(
                MessageType.FILE_TRANSFER,
                {"filename": filename}
            )
            peer_socket.send(message)

            with open(filename, 'wb') as f:
                while True:
                    data = peer_socket.recv(1024)
                    if not data:
                        break
                    f.write(data)

            self.file_manager.add_file(filename)
            return True
        except Exception as e:
            print(f"Error downloading file: {e}")
            return False
        finally:
            peer_socket.close()

    def list_files(self) -> List[str]:
        message = Protocol.create_message(MessageType.LIST_FILES, {})
        self.server_socket.send(message)
        response = self.server_socket.recv(1024)
        msg_type, data = Protocol.parse_message(response)

        if msg_type == MessageType.SUCCESS:
            return data["files"]
        return []

    def remove_file(self, filename: str) -> bool:
        message = Protocol.create_message(
            MessageType.REMOVE_FILE,
            {"filename": filename}
        )
        self.server_socket.send(message)
        response = self.server_socket.recv(1024)
        msg_type, data = Protocol.parse_message(response)

        if msg_type == MessageType.SUCCESS:
            self.file_manager.remove_file(filename)
            return True
        return False

    def disconnect(self):
        if self.state == ClientState.ONLINE:
            message = Protocol.create_message(MessageType.DISCONNECT, {})
            self.server_socket.send(message)
            self.state = ClientState.OFFLINE

    def reconnect(self):
        if self.state == ClientState.OFFLINE:
            self._connect_to_server()



