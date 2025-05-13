import socket
import threading
import json
import os
import logging
import time
import hashlib
import uuid
from argon2 import PasswordHasher
import secrets
from enum import Enum, auto
import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server_log.txt"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("CipherShare Server")

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

class ServerResponse(Enum):
    """Enum for different types of server responses"""
    SUCCESS = auto()
    FAILURE = auto()
    FILE_NOT_FOUND = auto()
    UNAUTHORIZED = auto()
    NO_ONLINE_CLIENTS = auto()
    FILE_ALREADY_EXISTS = auto()
    USER_ALREADY_EXISTS = auto()
    INVALID_CREDENTIALS = auto()
    SESSION_EXPIRED = auto()

class DatabaseManager:
    """Class to manage the database (text files)"""
    def __init__(self):
        # Create database directory if it doesn't exist
        if not os.path.exists('database'):
            os.makedirs('database')
        
        # Paths to database files
        self.files_db_path = 'database/files.json'
        self.users_db_path = 'database/users.json'
        self.sessions_db_path = 'database/sessions.json'
        
        # Initialize database files if they don't exist
        self.initialize_database()
    
    def initialize_database(self):
        """Initialize the database files if they don't exist"""
        # Initialize files database
        if not os.path.exists(self.files_db_path):
            with open(self.files_db_path, 'w') as f:
                json.dump([], f)
        
        # Initialize users database
        if not os.path.exists(self.users_db_path):
            with open(self.users_db_path, 'w') as f:
                json.dump([], f)
        
        # Initialize sessions database
        if not os.path.exists(self.sessions_db_path):
            with open(self.sessions_db_path, 'w') as f:
                json.dump([], f)
    
    def get_files(self):
        """Get all files from the database"""
        try:
            with open(self.files_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error getting files: {e}")
            return []
    
    def add_file(self, file_info):
        """Add a file to the database"""
        try:
            files = self.get_files()
            files.append(file_info)
            with open(self.files_db_path, 'w') as f:
                json.dump(files, f)
            return True
        except Exception as e:
            logger.error(f"Error adding file: {e}")
            return False
    
    def update_file(self, updated_file_info):
        """Update a specific file's information"""
        try:
            files = self.get_files()
            updated = False
            
            for i, file_info in enumerate(files):
                if (file_info['filename'] == updated_file_info['filename'] and
                    file_info['owner'] == updated_file_info['owner'] and
                    file_info['ip'] == updated_file_info['ip']):
                    # Update the file info
                    files[i] = updated_file_info
                    updated = True
                    break
            
            if updated:
                with open(self.files_db_path, 'w') as f:
                    json.dump(files, f)
                logger.info(f"Updated file info for {updated_file_info['filename']}")
                return True
            else:
                logger.warning(f"File not found for update: {updated_file_info['filename']}")
                return False
        except Exception as e:
            logger.error(f"Error updating file: {e}")
            return False
    
    def remove_file(self, username, filename, client_address):
        """Remove a file from the database"""
        try:
            files = self.get_files()
            updated_files = []
            file_found = False
            for file_info in files:
                # Keep the file if it's not the one we're removing
                # or if it's shared by other clients
                if (file_info['filename'] != filename or 
                    file_info['owner'] != username or 
                    file_info['ip'] != client_address[0]):
                    updated_files.append(file_info)
                else:
                    file_found = True
            
            if file_found:
                with open(self.files_db_path, 'w') as f:
                    json.dump(updated_files, f)
                return True
            return False
        except Exception as e:
            logger.error(f"Error removing file: {e}")
            return False
    
    def update_client_status(self, client_address, status):
        """Update the status of a client in all its files"""
        try:
            files = self.get_files()
            updated = False
            
            for file_info in files:
                # Ensure we're matching on IP - don't match on port as it might change
                if file_info['ip'] == client_address[0]:
                    file_info['online'] = status
                    updated = True
            
            if updated:
                with open(self.files_db_path, 'w') as f:
                    json.dump(files, f)
                logger.info(f"Updated status to {status} for client at {client_address[0]}")
                return True
            else:
                logger.warning(f"No files found for client at {client_address[0]}")
                return False
        except Exception as e:
            logger.error(f"Error updating client status: {e}")
            return False
    
    def get_users(self):
        """Get all users from the database"""
        try:
            with open(self.users_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error getting users: {e}")
            return []
    
    def add_user(self, user_info):
        """Add a user to the database"""
        try:
            users = self.get_users()
            users.append(user_info)
            with open(self.users_db_path, 'w') as f:
                json.dump(users, f)
            return True
        except Exception as e:
            logger.error(f"Error adding user: {e}")
            return False
    
    def get_user(self, username):
        """Get a user from the database"""
        try:
            users = self.get_users()
            for user in users:
                if user['username'] == username:
                    return user
            return None
        except Exception as e:
            logger.error(f"Error getting user: {e}")
            return None
    
    def get_sessions(self):
        """Get all sessions from the database"""
        try:
            with open(self.sessions_db_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error getting sessions: {e}")
            return []
    
    def add_session(self, session_info):
        """Add a session to the database"""
        try:
            sessions = self.get_sessions()
            sessions.append(session_info)
            with open(self.sessions_db_path, 'w') as f:
                json.dump(sessions, f)
            return True
        except Exception as e:
            logger.error(f"Error adding session: {e}")
            return False
    
    def update_session(self, session_id, new_expiry):
        """Update a session's expiry time"""
        try:
            sessions = self.get_sessions()
            for session in sessions:
                if session['session_id'] == session_id:
                    session['expiry'] = new_expiry
                    break
            
            with open(self.sessions_db_path, 'w') as f:
                json.dump(sessions, f)
            return True
        except Exception as e:
            logger.error(f"Error updating session: {e}")
            return False
    
    def remove_session(self, session_id):
        """Remove a session from the database"""
        try:
            sessions = self.get_sessions()
            sessions = [s for s in sessions if s['session_id'] != session_id]
            with open(self.sessions_db_path, 'w') as f:
                json.dump(sessions, f)
            return True
        except Exception as e:
            logger.error(f"Error removing session: {e}")
            return False
    
    def get_session(self, session_id):
        """Get a session from the database"""
        try:
            sessions = self.get_sessions()
            for session in sessions:
                if session['session_id'] == session_id:
                    return session
            return None
        except Exception as e:
            logger.error(f"Error getting session: {e}")
            return None
    
    def clean_expired_sessions(self):
        """Remove expired sessions"""
        try:
            current_time = time.time()
            sessions = self.get_sessions()
            active_sessions = [s for s in sessions if s['expiry'] > current_time]
            
            with open(self.sessions_db_path, 'w') as f:
                json.dump(active_sessions, f)
            
            return len(sessions) - len(active_sessions)  # Return number of removed sessions
        except Exception as e:
            logger.error(f"Error cleaning expired sessions: {e}")
            return 0


class SessionManager:
    """Class to manage user sessions"""
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.session_timeout = 300  # 5 minutes in seconds
        
        # Start session cleanup thread
        self.cleanup_thread = threading.Thread(target=self.cleanup_expired_sessions, daemon=True)
        self.cleanup_thread.start()
    
    def create_session(self, username, client_address):
        """Create a new session for a user"""
        session_id = str(uuid.uuid4())
        expiry_time = time.time() + self.session_timeout
        
        session_info = {
            'session_id': session_id,
            'username': username,
            'client_address': client_address,
            'expiry': expiry_time
        }
        
        if self.db_manager.add_session(session_info):
            return session_id
        return None
    
    def validate_session(self, session_id):
        """Validate if a session is valid and not expired"""
        session = self.db_manager.get_session(session_id)
        if session and session['expiry'] > time.time():
            # Update session expiry
            new_expiry = time.time() + self.session_timeout
            self.db_manager.update_session(session_id, new_expiry)
            return session
        return None
    
    def end_session(self, session_id):
        """End a user session"""
        return self.db_manager.remove_session(session_id)
    
    def cleanup_expired_sessions(self):
        """Periodically clean up expired sessions"""
        while True:
            removed = self.db_manager.clean_expired_sessions()
            if removed > 0:
                logger.info(f"Cleaned up {removed} expired sessions")
            time.sleep(60)  # Check every minute


class AuthManager:
    """Class to manage user authentication"""
    def __init__(self, db_manager):
        self.db_manager = db_manager
        self.ph = PasswordHasher()

    def hash_password_argon(self, password):
        """Hash a password using SHA-256 (for now, will upgrade to Argon2 later)"""
        # In a future phase, this will be upgraded to Argon2
        # return hashlib.sha256(password.encode()).hexdigest()
        """Hash a password using Argon2"""
        # Use Argon2id for password hashing
        hashed_password = self.ph.hash(password)
        return hashed_password

    def verify_password(self, password, hashed_password):
        """Verify a password using Argon2"""
        try:
            # Verify the password against the stored hash
            self.ph.verify(hashed_password, password)
            return True  # Password matches
        except:
            return False  # Password does not match
    
    def register_user(self, username, password, client_address):
        """Register a new user"""
        # Check if username already exists
        if self.db_manager.get_user(username):
            return None
        
        # Hash the password
        hashed_password = self.hash_password_argon(password)
        
        # Create user info
        user_info = {
            'username': username,
            'password_hash': hashed_password,
            'created_at': time.time(),
            'last_login': time.time(),
            'ip': client_address[0],
            'port': client_address[1]
        }
        
        # Add user to database
        if self.db_manager.add_user(user_info):
            return True
        return False

    # def authenticate_user(self, username, password):
    #     """Authenticate a user"""
    #     user = self.db_manager.get_user(username)
    #     if user:
    #         hashed_password = self.hash_password(password)
    #         if user['password_hash'] == hashed_password:
    #             return True
    #     return False
    def authenticate_user(self, username, password):
        """Authenticate a user using Argon2"""
        # Retrieve user from the database (including the password_hash)
        user = self.db_manager.get_user(username)

        if user:
            try:
                # Verify the entered password against the stored hash using Argon2
                self.ph.verify(user['password_hash'], password)
                return True  # Password matches
            except:
                return False  # Password does not match (verification failed)
        return False  # User not found


class ClientHandler:
    """Class to handle client connections"""
    def __init__(self, client_socket, client_address, db_manager, session_manager, auth_manager):
        self.client_socket = client_socket
        self.client_address = client_address
        self.db_manager = db_manager
        self.session_manager = session_manager
        self.auth_manager = auth_manager
        self.username = None
        self.session_id = None
        self.authenticated = False
    
    def handle_client(self):
        """Handle client requests"""
        try:
            while True:
                # Receive data from client
                data = self.receive_data()
                if not data:
                    break
                
                # Parse the message
                message = json.loads(data.decode('utf-8'))
                message_type = MessageType[message['type']]
                
                # Handle different message types
                if message_type == MessageType.REGISTER:
                    self.handle_register(message)
                elif message_type == MessageType.LOGIN:
                    self.handle_login(message)
                elif message_type == MessageType.SESSION_CHECK:
                    self.handle_session_check(message)
                else:
                    # For all other requests, check if user is authenticated
                    if not self.authenticated and not self.validate_session(message):
                        self.send_error("Authentication required")
                        continue
                    
                    # Handle authenticated requests
                    if message_type == MessageType.UPLOAD_FILE:
                        self.handle_upload_file(message)
                    elif message_type == MessageType.DOWNLOAD_FILE:
                        self.handle_download_file(message)
                    elif message_type == MessageType.LIST_FILES:
                        self.handle_list_files()
                    elif message_type == MessageType.REMOVE_FILE:
                        self.handle_remove_file(message)
                    elif message_type == MessageType.DISCONNECT:
                        self.handle_disconnect()
                        break
                    elif message_type == MessageType.RECONNECT:
                        self.handle_reconnect()
        except Exception as e:
            logger.error(f"Error handling client {self.client_address}: {e}")
        finally:
            # Always update client status to offline when connection ends
            self.db_manager.update_client_status(self.client_address, False)
            self.client_socket.close()
            logger.info(f"Connection closed with client {self.client_address}")
    
    def receive_data(self):
        """Receive data from client with length prefix"""
        # First receive the length of the message (4 bytes)
        length_prefix = self.client_socket.recv(4)
        if not length_prefix:
            return None
        
        # Convert length prefix to integer
        message_length = int.from_bytes(length_prefix, byteorder='big')
        
        # Receive the actual message
        chunks = []
        bytes_received = 0
        
        while bytes_received < message_length:
            chunk = self.client_socket.recv(min(4096, message_length - bytes_received))
            if not chunk:
                return None
            chunks.append(chunk)
            bytes_received += len(chunk)
        
        return b''.join(chunks)
    
    def send_data(self, data):
        """Send data to client with length prefix"""
        # Convert data to bytes if it's not already
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # Send length prefix followed by data
        length_prefix = len(data).to_bytes(4, byteorder='big')
        self.client_socket.sendall(length_prefix + data)
    
    def send_response(self, response_type, data=None):
        """Send a response to the client"""
        response = {
            'type': response_type.name,
            'data': data or {}
        }
        self.send_data(json.dumps(response))
    
    def send_error(self, error_message):
        """Send an error response to the client"""
        self.send_response(MessageType.ERROR, {'message': error_message})
    
    def validate_session(self, message):
        """Validate session from message"""
        if 'session_id' in message:
            session = self.session_manager.validate_session(message['session_id'])
            if session:
                self.session_id = message['session_id']
                self.username = session['username']
                self.authenticated = True
                return True
        return False
    
    def handle_register(self, message):
        """Handle user registration"""
        username = message['username']
        password = message['password']
        
        # Register the user
        result = self.auth_manager.register_user(username, password, self.client_address)
        
        if result:
            # Create a session for the newly registered user
            session_id = self.session_manager.create_session(username, self.client_address)
            if session_id:
                self.username = username
                self.session_id = session_id
                self.authenticated = True
                
                self.send_response(MessageType.SUCCESS, {
                    'message': 'Registration successful',
                    'session_id': session_id
                })
                logger.info(f"User '{username}' registered successfully from {self.client_address}")
            else:
                self.send_error("Failed to create session")
        else:
            self.send_response(MessageType.ERROR, {
                'message': 'Username already exists or registration failed'
            })
    
    def handle_login(self, message):
        """Handle user login"""
        username = message['username']
        password = message['password']
        
        # Authenticate the user
        if self.auth_manager.authenticate_user(username, password):
            # Create a session for the authenticated user
            session_id = self.session_manager.create_session(username, self.client_address)
            if session_id:
                self.username = username
                self.session_id = session_id
                self.authenticated = True
                
                self.send_response(MessageType.SUCCESS, {
                    'message': 'Login successful',
                    'session_id': session_id
                })
                logger.info(f"User '{username}' logged in successfully from {self.client_address}")
            else:
                self.send_error("Failed to create session")
        else:
            self.send_response(MessageType.ERROR, {
                'message': 'Invalid username or password'
            })
    
    def handle_session_check(self, message):
        """Handle session validation"""
        if 'session_id' in message:
            session = self.session_manager.validate_session(message['session_id'])
            if session:
                self.session_id = message['session_id']
                self.username = session['username']
                self.authenticated = True
                
                self.send_response(MessageType.SUCCESS, {
                    'message': 'Session valid',
                    'username': self.username
                })
                return
        
        self.send_response(MessageType.ERROR, {
            'message': 'Session expired or invalid'
        })

    def handle_upload_file(self, message):
        """Handle file upload request"""
        filename = message['filename']
        
        # Get the file sharing port of the client (could be different from the connection port)
        client_port = message.get('client_port', self.client_address[1])
        logger.info(f"Client {self.username} is sharing file '{filename}' from port {client_port}")
        
        # Check if file already exists
        existing_files = self.db_manager.get_files()
        for file_info in existing_files:
            if (file_info['filename'] == filename and 
                file_info['owner'] == self.username and
                file_info['ip'] == self.client_address[0]):
                # Update the file info to ensure client is marked as online and port is current
                file_info['online'] = True
                file_info['port'] = client_port  # Update the port to the listening port
                if self.db_manager.update_file(file_info):
                    self.send_response(MessageType.SUCCESS, {
                        'message': 'File info updated, you are still sharing this file'
                    })
                else:
                    self.send_response(MessageType.ERROR, {
                        'message': 'Failed to update file info'
                    })
                return
        
        # Add file to database
        file_info = {
            'filename': filename,
            'owner': self.username,
            'ip': self.client_address[0],
            'port': client_port,  # Use the listening port, not the connection port
            'online': True,
            'uploaded_at': time.time()
        }
        
        if self.db_manager.add_file(file_info):
            self.send_response(MessageType.SUCCESS, {
                'message': f'File "{filename}" is now available for sharing'
            })
            logger.info(f"User '{self.username}' uploaded file '{filename}' (port {client_port})")
        else:
            self.send_error("Failed to share file")
    
    def handle_download_file(self, message):
        """Handle file download request"""
        filename = message['filename']
        
        # Find all clients that have this file
        available_clients = []
        files = self.db_manager.get_files()
        
        logger.info(f"Looking for file '{filename}' requested by '{self.username}'")

        for file_info in files:
            if file_info['filename'] == filename and file_info['online']:
                logger.info(f"Found match: owner={file_info['owner']}, ip={file_info['ip']}, port={file_info['port']}, online={file_info['online']}")
                available_clients.append({
                    'owner': file_info['owner'],
                    'ip': file_info['ip'],
                    'port': file_info['port']
                })

        if not available_clients:
            logger.warning(f"No online clients found with file '{filename}'")
            self.send_response(MessageType.ERROR, {
                'message': f'File "{filename}" not found or no online clients have it'
            })
            return
        
        # Select the first available client
        selected_client = available_clients[0]
        logger.info(f"Selected client: {selected_client['owner']} at {selected_client['ip']}:{selected_client['port']}")
        
        # Inform the selected client about the download request
        try:
            # Create a temporary socket to inform the file owner
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as temp_socket:
                temp_socket.settimeout(5)  # Set a timeout for connection attempts
                temp_socket.connect((selected_client['ip'], int(selected_client['port'])))
                
                # Send file request notification
                notification = {
                    'type': MessageType.FILE_INFO.name,
                    'requester_ip': self.client_address[0],
                    'requester_port': self.client_address[1],
                    'requester_username': self.username,
                    'filename': filename
                }
                
                # Send with length prefix
                notification_bytes = json.dumps(notification).encode('utf-8')
                length_prefix = len(notification_bytes).to_bytes(4, byteorder='big')
                temp_socket.sendall(length_prefix + notification_bytes)
                logger.info(f"Sent notification to file owner")
        except Exception as e:
            logger.error(f"Failed to notify file owner: {e}")
            # Mark the client as offline
            self.db_manager.update_client_status((selected_client['ip'], int(selected_client['port'])), False)
            
            # Try again with another client if available
            if len(available_clients) > 1:
                logger.info(f"Trying next available client...")
                # Remove the failed client and try again
                message['_tried_clients'] = message.get('_tried_clients', []) + [selected_client]
                self.handle_download_file(message)
                return
            else:
                self.send_response(MessageType.ERROR, {
                    'message': f'File "{filename}" found but all clients are unreachable'
                })
                return
        
        # Send the client info to the requester
        self.send_response(MessageType.SUCCESS, {
            'message': f'Found client sharing "{filename}"',
            'client_info': selected_client
        })
        
        logger.info(f"User '{self.username}' requested download of '{filename}' from '{selected_client['owner']}'")
    
    def handle_list_files(self):
        """Handle request to list available files"""
        files = self.db_manager.get_files()
        
        # Filter to only show online files
        online_files = []
        for file_info in files:
            if file_info['online']:
                online_files.append({
                    'filename': file_info['filename'],
                    'owner': file_info['owner']
                })
        
        self.send_response(MessageType.SUCCESS, {
            'files': online_files
        })
    
    def handle_remove_file(self, message):
        """Handle file removal request"""
        filename = message['filename']
        
        if self.db_manager.remove_file(self.username, filename, self.client_address):
            self.send_response(MessageType.SUCCESS, {
                'message': f'File "{filename}" removed successfully'
            })
            logger.info(f"User '{self.username}' removed file '{filename}'")
        else:
            self.send_response(MessageType.ERROR, {
                'message': f'File "{filename}" not found or you do not have permission to remove it'
            })
    
    def handle_disconnect(self):
        """Handle client disconnect request"""
        # Update client status to offline
        self.db_manager.update_client_status(self.client_address, False)
        
        # End the session if it exists
        if self.session_id:
            self.session_manager.end_session(self.session_id)
        
        self.send_response(MessageType.SUCCESS, {
            'message': 'Disconnected successfully'
        })
        
        logger.info(f"User '{self.username}' disconnected from {self.client_address}")
    
    def handle_reconnect(self):
        """Handle client reconnect request"""
        # Update client status to online
        self.db_manager.update_client_status(self.client_address, True)
        
        self.send_response(MessageType.SUCCESS, {
            'message': 'Reconnected successfully'
        })
        
        logger.info(f"User '{self.username}' reconnected from {self.client_address}")


class CipherShareServer:
    """Main server class"""
    def __init__(self, host='0.0.0.0', port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        self.db_manager = DatabaseManager()
        self.session_manager = SessionManager(self.db_manager)
        self.auth_manager = AuthManager(self.db_manager)
        
        # Set to store client handlers
        self.clients = set()
    
    def start(self):
        """Start the server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            logger.info(f"Server started on {self.host}:{self.port}")
            
            print(f"CipherShare Server running on {self.host}:{self.port}")
            print("Press Ctrl+C to stop the server")
            
            while True:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"New connection from {client_address}")
                
                # Create a new client handler for this connection
                client_handler = ClientHandler(
                    client_socket, 
                    client_address,
                    self.db_manager,
                    self.session_manager,
                    self.auth_manager
                )
                
                # Start a new thread to handle this client
                client_thread = threading.Thread(target=client_handler.handle_client, daemon=True)
                client_thread.start()
                
                # Add to clients set
                self.clients.add(client_handler)
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
            logger.info("Server stopped")
    
    def stop(self):
        """Stop the server"""
        if self.server_socket:
            self.server_socket.close()
            logger.info("Server stopped")


def main():
    """Main function to start the server"""
    server = CipherShareServer()
    server.start()


if __name__ == "__main__":
    main()