import socket
import threading
import json
import os
import sys
import time
import logging
from enum import Enum, auto

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CipherShare Client")

class MessageType(Enum):
    """Enum for different types of messages between client and server"""
    REGISTER = auto()
    LOGIN = auto()
    UPLOAD_FILE = auto()
    DOWNLOAD_FILE = auto()
    LIST_FILES = auto()
    REMOVE_FILE = auto()
    DISCONNECT = auto()
    RECONNECT = auto()
    ERROR = auto()
    SUCCESS = auto()
    FILE_INFO = auto()
    SESSION_CHECK = auto()
    FILE_TRANSFER = auto()
    FILE_TRANSFER_COMPLETE = auto()

class ClientState(Enum):
    """Enum for different states of the client"""
    DISCONNECTED = auto()
    CONNECTED = auto()
    AUTHENTICATED = auto()


class FileSharingClient:
    """Client class for sharing files in the P2P network"""
    
    def __init__(self, server_host='localhost', server_port=5555, client_port=0):
        # Server connection details
        self.server_host = server_host
        self.server_port = server_port
        
        # Client details
        self.client_port = client_port  # 0 means any available port
        self.client_socket = None
        self.server_socket = None
        self.listen_socket = None
        self.listen_thread = None
        
        # Client state
        self.state = ClientState.DISCONNECTED
        self.username = None
        self.session_id = None
        
        # File management
        self.shared_files_path = 'shared_files'
        self.downloaded_files_path = 'downloaded_files'
        self.shared_files = []
        
        # Create directories if they don't exist
        if not os.path.exists(self.shared_files_path):
            os.makedirs(self.shared_files_path)
        if not os.path.exists(self.downloaded_files_path):
            os.makedirs(self.downloaded_files_path)
        
        # Load shared files
        self.load_shared_files()
    
    def connect_to_server(self):
        """Connect to the server"""
        try:
            # Create socket to connect to server
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((self.server_host, self.server_port))
            
            # Create listening socket for file transfers
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.bind(('0.0.0.0', self.client_port))
            self.listen_socket.listen(5)
            
            # Get the actual port assigned
            _, self.client_port = self.listen_socket.getsockname()
            
            logger.info(f"Connected to server at {self.server_host}:{self.server_port}")
            logger.info(f"Listening for file transfers on port {self.client_port}")
            
            # Start listening for file transfer requests
            self.listen_thread = threading.Thread(target=self.listen_for_file_transfers, daemon=True)
            self.listen_thread.start()
            
            # Update state
            self.state = ClientState.CONNECTED
            
            return True
        except Exception as e:
            logger.error(f"Failed to connect to server: {e}")
            return False
    
    def register(self, username, password):
        """Register a new user"""
        if self.state == ClientState.DISCONNECTED:
            if not self.connect_to_server():
                return False, "Failed to connect to server"
        
        # Create register message
        message = {
            'type': MessageType.REGISTER.name,
            'username': username,
            'password': password
        }
        
        # Send register request
        response = self.send_and_receive(message)
        
        if response and response['type'] == MessageType.SUCCESS.name:
            self.username = username
            self.session_id = response['data']['session_id']
            self.state = ClientState.AUTHENTICATED
            logger.info(f"Registered as {username}")
            return True, "Registration successful"
        else:
            error_msg = response['data']['message'] if response else "No response from server"
            logger.error(f"Registration failed: {error_msg}")
            return False, f"Registration failed: {error_msg}"
    
    def login(self, username, password):
        """Login with username and password"""
        if self.state == ClientState.DISCONNECTED:
            if not self.connect_to_server():
                return False, "Failed to connect to server"
        
        # Create login message
        message = {
            'type': MessageType.LOGIN.name,
            'username': username,
            'password': password
        }
        
        # Send login request
        response = self.send_and_receive(message)
        
        if response and response['type'] == MessageType.SUCCESS.name:
            self.username = username
            self.session_id = response['data']['session_id']
            self.state = ClientState.AUTHENTICATED
            logger.info(f"Logged in as {username}")
            return True, "Login successful"
        else:
            error_msg = response['data']['message'] if response else "No response from server"
            logger.error(f"Login failed: {error_msg}")
            return False, f"Login failed: {error_msg}"
    
    def check_session(self):
        """Check if the current session is valid"""
        if not self.session_id:
            return False
        
        # Create session check message
        message = {
            'type': MessageType.SESSION_CHECK.name,
            'session_id': self.session_id
        }
        
        # Send session check request
        response = self.send_and_receive(message)
        
        if response and response['type'] == MessageType.SUCCESS.name:
            logger.info("Session is valid")
            return True
        else:
            logger.warning("Session is invalid or expired")
            self.state = ClientState.CONNECTED
            self.session_id = None
            return False
    
    def disconnect(self):
        """Disconnect from the server"""
        if self.state == ClientState.DISCONNECTED:
            return True, "Already disconnected"
        
        # Create disconnect message
        message = {
            'type': MessageType.DISCONNECT.name,
            'session_id': self.session_id
        }
        
        # Send disconnect request
        response = self.send_and_receive(message)
        
        success = response and response['type'] == MessageType.SUCCESS.name
        
        # Close sockets
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        
        # Update state
        self.state = ClientState.DISCONNECTED
        
        if success:
            logger.info("Disconnected from server")
            return True, "Disconnected successfully"
        else:
            logger.error("Failed to disconnect gracefully")
            return False, "Failed to disconnect gracefully"
    
    def reconnect(self):
        """Reconnect to the server"""
        if self.state != ClientState.DISCONNECTED:
            return True, "Already connected"
        
        if not self.connect_to_server():
            return False, "Failed to connect to server"
        
        if not self.session_id:
            return True, "Connected but not authenticated"
        
        # Try to restore session
        if self.check_session():
            self.state = ClientState.AUTHENTICATED
            logger.info("Reconnected and session restored")
            return True, "Reconnected and session restored"
        else:
            logger.info("Reconnected but session expired")
            return True, "Reconnected but need to login again"
    
    def upload_file(self, file_path):
        """Inform the server about a file available for sharing"""
        if self.state != ClientState.AUTHENTICATED:
            return False, "Not authenticated"
        
        # Check if file exists
        if not os.path.isfile(file_path):
            return False, f"File '{file_path}' not found"
        
        # Get file name from path
        filename = os.path.basename(file_path)
        
        # Copy file to shared directory if not already there
        target_path = os.path.join(self.shared_files_path, filename)
        if file_path != target_path:
            try:
                with open(file_path, 'rb') as src, open(target_path, 'wb') as dst:
                    dst.write(src.read())
            except Exception as e:
                logger.error(f"Failed to copy file to shared directory: {e}")
                return False, f"Failed to copy file: {e}"
        
        # Create upload message
        message = {
            'type': MessageType.UPLOAD_FILE.name,
            'session_id': self.session_id,
            'filename': filename,
            'client_port': self.client_port  # Send the listening port to the server
        }
        
        # Send upload request
        response = self.send_and_receive(message)
        
        if response and response['type'] == MessageType.SUCCESS.name:
            # Add to shared files list if not already there
            if filename not in self.shared_files:
                self.shared_files.append(filename)
                self.save_shared_files()
            
            logger.info(f"File '{filename}' uploaded successfully")
            return True, f"File '{filename}' is now available for sharing"
        else:
            error_msg = response['data']['message'] if response else "No response from server"
            logger.error(f"Upload failed: {error_msg}")
            return False, f"Upload failed: {error_msg}"
    
    def download_file(self, filename):
        """Download a file from another client"""
        if self.state != ClientState.AUTHENTICATED:
            return False, "Not authenticated"
        
        # Create download request message
        message = {
            'type': MessageType.DOWNLOAD_FILE.name,
            'session_id': self.session_id,
            'filename': filename
        }
        
        # Send download request
        response = self.send_and_receive(message)
        
        if response and response['type'] == MessageType.SUCCESS.name:
            client_info = response['data']['client_info']
            logger.info(f"Received file source information: {client_info}")
            
            # Create socket to connect to file owner
            try:
                file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                file_socket.settimeout(10)  # Add timeout for connection
                file_socket.connect((client_info['ip'], int(client_info['port'])))
                logger.info(f"Connected to file source at {client_info['ip']}:{client_info['port']}")
                
                # Create file request message
                file_request = {
                    'type': MessageType.FILE_TRANSFER.name,
                    'filename': filename,
                    'requester_username': self.username
                }
                
                # Send file request with length prefix
                self.send_data(file_socket, json.dumps(file_request))
                logger.info(f"Sent file transfer request")
                
                # Receive file data
                file_data = self.receive_file(file_socket)
                logger.info(f"Received file data: {len(file_data) if file_data else 'None'} bytes")
                
                if file_data:
                    # Save file to downloaded directory
                    download_path = os.path.join(self.downloaded_files_path, filename)
                    with open(download_path, 'wb') as f:
                        f.write(file_data)
                    
                    # Add to shared files list
                    if filename not in self.shared_files:
                        self.shared_files.append(filename)
                        self.save_shared_files()
                    
                    # Upload the file to server to mark as available
                    self.upload_file(download_path)
                    
                    logger.info(f"File '{filename}' downloaded successfully")
                    return True, f"File '{filename}' downloaded successfully"
                else:
                    logger.error(f"Failed to download file '{filename}'")
                    return False, f"Failed to download file '{filename}'"
            except Exception as e:
                logger.error(f"Download error: {e}")
                return False, f"Download error: {e}"
            finally:
                if 'file_socket' in locals() and file_socket:
                    file_socket.close()
        else:
            error_msg = response['data']['message'] if response else "No response from server"
            logger.error(f"Download request failed: {error_msg}")
            return False, f"Download request failed: {error_msg}"
    
    def list_files(self):
        """List files available for download"""
        if self.state != ClientState.AUTHENTICATED:
            return False, "Not authenticated", []
        
        # Create list files message
        message = {
            'type': MessageType.LIST_FILES.name,
            'session_id': self.session_id
        }
        
        # Send list files request
        response = self.send_and_receive(message)
        
        if response and response['type'] == MessageType.SUCCESS.name:
            files = response['data']['files']
            logger.info(f"Retrieved {len(files)} available files")
            return True, f"Retrieved {len(files)} available files", files
        else:
            error_msg = response['data']['message'] if response else "No response from server"
            logger.error(f"List files failed: {error_msg}")
            return False, f"List files failed: {error_msg}", []
    
    def remove_file(self, filename):
        """Remove a shared file"""
        if self.state != ClientState.AUTHENTICATED:
            return False, "Not authenticated"
        
        # Check if file is in shared files
        if filename not in self.shared_files:
            return False, f"File '{filename}' is not being shared"
        
        # Create remove file message
        message = {
            'type': MessageType.REMOVE_FILE.name,
            'session_id': self.session_id,
            'filename': filename
        }
        
        # Send remove file request
        response = self.send_and_receive(message)
        
        if response and response['type'] == MessageType.SUCCESS.name:
            # Remove from shared files list
            self.shared_files.remove(filename)
            self.save_shared_files()
            
            logger.info(f"File '{filename}' removed successfully")
            return True, f"File '{filename}' removed successfully"
        else:
            error_msg = response['data']['message'] if response else "No response from server"
            logger.error(f"Remove file failed: {error_msg}")
            return False, f"Remove file failed: {error_msg}"
    
    def load_shared_files(self):
        """Load list of shared files from file"""
        try:
            shared_files_list_path = 'shared_files_list.json'
            if os.path.exists(shared_files_list_path):
                with open(shared_files_list_path, 'r') as f:
                    self.shared_files = json.load(f)
                logger.info(f"Loaded {len(self.shared_files)} shared files")
            else:
                self.shared_files = []
                logger.info("No shared files list found, starting fresh")
        except Exception as e:
            logger.error(f"Failed to load shared files list: {e}")
            self.shared_files = []
    
    def save_shared_files(self):
        """Save list of shared files to file"""
        try:
            shared_files_list_path = 'shared_files_list.json'
            with open(shared_files_list_path, 'w') as f:
                json.dump(self.shared_files, f)
            logger.info(f"Saved {len(self.shared_files)} shared files")
        except Exception as e:
            logger.error(f"Failed to save shared files list: {e}")
    
    def listen_for_file_transfers(self):
        """Listen for file transfer requests from other clients"""
        try:
            logger.info(f"Starting to listen for file transfers on port {self.client_port}")
            while True:
                # Accept connection from file requester
                client_socket, client_address = self.listen_socket.accept()
                logger.info(f"Received connection from {client_address}")
                
                # Start a new thread to handle file transfer
                transfer_thread = threading.Thread(
                    target=self.handle_file_transfer,
                    args=(client_socket, client_address),
                    daemon=True
                )
                transfer_thread.start()
        except Exception as e:
            logger.error(f"File transfer listening error: {e}")
        finally:
            if self.listen_socket:
                self.listen_socket.close()
                logger.info("File transfer listening socket closed")
    
    def handle_file_transfer(self, client_socket, client_address):
        """Handle file transfer request from another client"""
        try:
            logger.info(f"Handling file transfer request from {client_address}")
            # Receive file request
            data = self.receive_data(client_socket)
            if not data:
                logger.error("No data received in file transfer request")
                return
            
            request = json.loads(data.decode('utf-8'))
            logger.info(f"Received file transfer request: {request}")
            
            if request['type'] == MessageType.FILE_TRANSFER.name:
                filename = request['filename']
                requester_username = request['requester_username']
                
                logger.info(f"File transfer request for '{filename}' from {requester_username}")
                
                # Check if we have the file
                file_path = os.path.join(self.shared_files_path, filename)
                if not os.path.isfile(file_path):
                    logger.error(f"File '{filename}' not found in shared directory")
                    # Send error response
                    error_response = {
                        'type': MessageType.ERROR.name,
                        'message': f"File '{filename}' not found"
                    }
                    self.send_data(client_socket, json.dumps(error_response))
                    return
                
                # Read file data
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                
                logger.info(f"Sending file '{filename}' ({len(file_data)} bytes) to {requester_username}")
                
                # Send file data
                client_socket.sendall(len(file_data).to_bytes(4, byteorder='big'))
                client_socket.sendall(file_data)
                
                logger.info(f"File '{filename}' sent to {requester_username}")
            elif request['type'] == MessageType.FILE_INFO.name:
                # This is a notification from the server about an upcoming file transfer
                requester_ip = request['requester_ip']
                requester_port = request['requester_port']
                requester_username = request['requester_username']
                filename = request['filename']
                
                logger.info(f"File request notification: {requester_username} at {requester_ip}:{requester_port} will download '{filename}'")
                
                # Send acknowledgment
                ack_response = {
                    'type': MessageType.SUCCESS.name,
                    'message': "Notification received"
                }
                self.send_data(client_socket, json.dumps(ack_response))
        except Exception as e:
            logger.error(f"File transfer error: {e}")
            try:
                # Try to send error response
                error_response = {
                    'type': MessageType.ERROR.name,
                    'message': f"Transfer error: {str(e)}"
                }
                self.send_data(client_socket, json.dumps(error_response))
            except:
                pass
        finally:
            client_socket.close()
            logger.info(f"Closed connection with {client_address}")
    
    
    def receive_file(self, socket):
        """Receive file data from socket"""
        try:
            # First receive the length of the file
            length_bytes = socket.recv(4)
            if not length_bytes:
                return None
            
            file_length = int.from_bytes(length_bytes, byteorder='big')
            
            # Receive the file data
            chunks = []
            bytes_received = 0
            
            while bytes_received < file_length:
                chunk = socket.recv(min(4096, file_length - bytes_received))
                if not chunk:
                    return None
                chunks.append(chunk)
                bytes_received += len(chunk)
            
            return b''.join(chunks)
        except Exception as e:
            logger.error(f"Receive file error: {e}")
            return None
    
    def send_and_receive(self, message):
        """Send a message to the server and receive the response"""
        try:
            # Send the message
            self.send_data(self.server_socket, json.dumps(message))
            
            # Receive the response
            response_data = self.receive_data(self.server_socket)
            if not response_data:
                logger.error("No response received from server")
                return None
            
            # Parse the response
            response = json.loads(response_data.decode('utf-8'))
            return response
        except Exception as e:
            logger.error(f"Send and receive error: {e}")
            return None
    
    def send_data(self, sock, data):
        """Send data with length prefix"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Send length prefix followed by data
        length_prefix = len(data).to_bytes(4, byteorder='big')
        sock.sendall(length_prefix + data)
    
    def receive_data(self, sock):
        """Receive data with length prefix"""
        # First receive the length of the message
        length_prefix = sock.recv(4)
        if not length_prefix:
            return None
        
        # Convert length prefix to integer
        message_length = int.from_bytes(length_prefix, byteorder='big')
        
        # Receive the actual message
        chunks = []
        bytes_received = 0
        
        while bytes_received < message_length:
            chunk = sock.recv(min(4096, message_length - bytes_received))
            if not chunk:
                return None
            chunks.append(chunk)
            bytes_received += len(chunk)
        
        return b''.join(chunks)