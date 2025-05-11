import socket
import threading
import json
import os
import sys
import time
import logging
import base64
from enum import Enum, auto
# ─── Insert here ──────────────────────────────────────────────────────────────
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
# Import the crypto utilities
from simplified_crypto_utils import DiffieHellman, FileEncryption, FileIntegrity, derive_key

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
    # New message types for Phase 3
    DH_INIT = auto()
    DH_RESPONSE = auto()
    FILE_HASH = auto()

class ClientState(Enum):
    """Enum for different states of the client"""
    DISCONNECTED = auto()
    CONNECTED = auto()
    AUTHENTICATED = auto()

class ClientSideEncryption:
    def __init__(self, key=None):
        self.key = key or os.urandom(32)
    def encrypt_data(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded = padder.update(data.encode()) + padder.finalize()
        ct = encryptor.update(padded) + encryptor.finalize()
        return base64.b64encode(iv+ct).decode()

    def decrypt_data(self, blob):
        raw = base64.b64decode(blob)
        iv, ct = raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded) + unpadder.finalize()
        return data.decode()
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
        self._creds_file = 'encrypted_credentials.json'
        self._enc = ClientSideEncryption()
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
            # Store encrypted credentials locally
            encrypted_password = self._enc.encrypt_data(password)
            with open(self._creds_file, 'w') as f:
                json.dump({'username': username, 'password': encrypted_password}, f)
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
            # Store encrypted credentials locally
            encrypted_password = self._enc.encrypt_data(password)
            with open(self._creds_file, 'w') as f:
                json.dump({'username': username, 'password': encrypted_password}, f)

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
                # with open(file_path, 'rb') as src, open(target_path, 'wb') as dst:
                #     dst.write(src.read())
                # Derive encryption key from password
                if file_path.startswith(self.shared_files_path):
                    logger.error("Refusing to re-encrypt a file that is already encrypted and stored")
                    return False, "Cannot re-encrypt already encrypted file"

                logger.info("-" * 50)
                logger.info(f"Encrypting '{filename}' for secure storage (at rest)")
                with open(self._creds_file) as f:
                    creds = json.load(f)
                password = self._enc.decrypt_data(creds['password'])
                salt = os.urandom(16)
                key = derive_key(password, salt)
                logger.info("Derived AES encryption key using PBKDF2 with random salt")
                # Encrypt the file
                with open(file_path, 'rb') as f:
                    plaintext = f.read()
                iv, ciphertext = FileEncryption.encrypt_file(plaintext, key)
                logger.info(f"File encrypted using AES-256-CBC (IV: {iv.hex()})")

                # Save salt + iv + ciphertext
                with open(target_path, 'wb') as f:
                    f.write(salt + iv + ciphertext)
                    logger.info(f"Encrypted file stored securely at: {target_path}")
            # except Exception as e:
            #     logger.error(f"Failed to copy file to shared directory: {e}")
            #     return False, f"Failed to copy file: {e}"
            except Exception as e:
                logger.error(f"Encryption or file preparation failed: {e}")
                return False, f"Failed to prepare encrypted file: {e}"

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
        """Download a file from another client with encryption and integrity verification"""
        if self.state != ClientState.AUTHENTICATED:
            return False, "Not authenticated"

        logger.info("=" * 60)
        logger.info(" STARTING SECURE FILE DOWNLOAD PROCESS")
        logger.info("=" * 60)

        # Create download request message
        message = {
            'type': MessageType.DOWNLOAD_FILE.name,
            'session_id': self.session_id,
            'filename': filename
        }

        # Send download request
        logger.info(" Sending download request to server")
        response = self.send_and_receive(message)

        if response and response['type'] == MessageType.SUCCESS.name:
            client_info = response['data']['client_info']
            logger.info(f" Server provided file source: {client_info['owner']} at {client_info['ip']}:{client_info['port']}")

            # Create socket to connect to file owner
            try:
                logger.info("-" * 50)
                logger.info(" ESTABLISHING CONNECTION TO FILE OWNER")
                file_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                file_socket.settimeout(15)  # Increased timeout for more reliability
                file_socket.connect((client_info['ip'], int(client_info['port'])))
                logger.info(f" Connected to file source at {client_info['ip']}:{client_info['port']}")

                # Create file request message
                file_request = {
                    'type': MessageType.FILE_TRANSFER.name,
                    'filename': filename,
                    'requester_username': self.username
                }

                # Send file request with length prefix
                self.send_data(file_socket, json.dumps(file_request))
                logger.info(f" Sent file transfer request for '{filename}'")

                # --- Phase 3: Diffie-Hellman Key Exchange ---
                logger.info("-" * 50)
                logger.info(" INITIATING DIFFIE-HELLMAN KEY EXCHANGE (RECEIVER)")

                # Initialize Diffie-Hellman
                logger.info(" Initializing Diffie-Hellman key exchange")
                dh = DiffieHellman()

                # Send DH initialization with our public key
                dh_init = {
                    'type': MessageType.DH_INIT.name,
                    'public_key': dh.get_public_key()
                }
                self.send_data(file_socket, json.dumps(dh_init))
                logger.info(" Sent our public key to file owner")

                # Receive DH response with other client's public key
                logger.info(" Waiting for file owner's public key...")
                dh_data = self.receive_data(file_socket)
                if not dh_data:
                    logger.error(" No DH response received")
                    return False, "Key exchange failed - no response from file owner"

                dh_response = json.loads(dh_data.decode('utf-8'))
                if dh_response['type'] != MessageType.DH_RESPONSE.name:
                    logger.error(f" Unexpected message type: {dh_response['type']}")
                    return False, "Key exchange protocol error - incorrect response type"

                # Compute shared key
                other_public_key = dh_response['public_key']
                logger.info(" Received file owner's public key")

                shared_key = dh.compute_shared_key(other_public_key)
                logger.info(" Successfully computed shared encryption key")
                logger.info(" DIFFIE-HELLMAN KEY EXCHANGE COMPLETED")

                # --- Receive File Hash for Integrity Verification ---
                logger.info("-" * 50)
                logger.info(" RECEIVING FILE INTEGRITY HASH")
                hash_data = self.receive_data(file_socket)
                if not hash_data:
                    logger.error(" No file hash received")
                    return False, "Failed to receive file hash for integrity verification"

                hash_message = json.loads(hash_data.decode('utf-8'))
                if hash_message['type'] != MessageType.FILE_HASH.name:
                    logger.error(f" Unexpected message type: {hash_message['type']}")
                    return False, "Protocol error during integrity verification"

                expected_hash = bytes.fromhex(hash_message['hash'])
                logger.info(" Received file integrity hash from sender")

                # --- Receive Encrypted File ---
                logger.info("-" * 50)
                logger.info(" RECEIVING ENCRYPTED FILE")
                logger.info(" Waiting for encrypted file data...")
                encrypted_data = self.receive_file(file_socket)

                if encrypted_data:
                    logger.info(f" Received encrypted file: {len(encrypted_data)} bytes")

                    # Extract IV (first 16 bytes) and ciphertext
                    logger.info("-" * 50)
                    logger.info(" DECRYPTING FILE")
                    iv = encrypted_data[:16]
                    ciphertext = encrypted_data[16:]
                    logger.info(f" Extracted IV (16 bytes) and ciphertext ({len(ciphertext)} bytes)")

                    # Decrypt file
                    try:
                        file_data = FileEncryption.decrypt_file(ciphertext, iv, shared_key)
                        logger.info(f" Successfully decrypted file (size: {len(file_data)} bytes)")

                        # Verify file integrity
                        logger.info("-" * 50)
                        logger.info(" VERIFYING FILE INTEGRITY")
                        if not FileIntegrity.verify_hash(file_data, expected_hash):
                            logger.error(" SECURITY ALERT: File integrity verification failed!")
                            return False, "Security alert: File integrity verification failed - possible tampering detected"

                        logger.info(" File integrity verified - hash matches!")

                        # Save file to downloaded directory
                        logger.info("-" * 50)
                        logger.info(" SAVING DECRYPTED FILE")
                        download_path = os.path.join(self.downloaded_files_path, filename)
                        with open(download_path, 'wb') as f:
                            f.write(file_data)
                        logger.info(f" File saved to {download_path}")

                        # Add to shared files list
                        if filename not in self.shared_files:
                            self.shared_files.append(filename)
                            self.save_shared_files()
                            logger.info(" Added file to shared files list")

                        # Upload the file to server to mark as available
                        logger.info(" Registering file as available from this client")
                        self.upload_file(download_path)

                        logger.info("=" * 60)
                        logger.info(" SECURE FILE DOWNLOAD COMPLETED SUCCESSFULLY")
                        logger.info("=" * 60)
                        return True, f"File '{filename}' downloaded successfully with encryption and integrity verification"
                    except Exception as e:
                        logger.error(f" Decryption error: {e}")
                        return False, f"Failed to decrypt file: {e}"
                else:
                    logger.error(" Failed to download encrypted file - no data received")
                    return False, f"Failed to download encrypted file - connection error or timeout"
            except socket.timeout:
                logger.error(" Connection timed out during file transfer")
                return False, "Connection timed out during file transfer"
            except Exception as e:
                logger.error(f" Download error: {e}")
                return False, f"Download error: {e}"
            finally:
                if 'file_socket' in locals() and file_socket:
                    file_socket.close()
                    logger.info(" Closed connection to file owner")
        else:
            error_msg = response['data']['message'] if response else "No response from server"
            logger.error(f" Download request failed: {error_msg}")
            return False, f"Download request failed: {error_msg}"

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

    # def handle_file_transfer(self, client_socket, client_address):
    #     """Handle file transfer request from another client (with encryption and integrity verification)"""
    #     try:
    #         logger.info("=" * 60)
    #         logger.info(" HANDLING INCOMING FILE TRANSFER REQUEST")
    #         logger.info("=" * 60)
    #         logger.info(f" Received connection from {client_address}")
    #
    #         # Receive file request
    #         data = self.receive_data(client_socket)
    #         if not data:
    #             logger.error(" No data received in file transfer request")
    #             return
    #
    #         request = json.loads(data.decode('utf-8'))
    #         logger.info(f" Received request of type: {request['type']}")
    #
    #         if request['type'] == MessageType.FILE_TRANSFER.name:
    #             filename = request['filename']
    #             requester_username = request['requester_username']
    #
    #             logger.info(f" File transfer request for '{filename}' from {requester_username}")
    #
    #             # Check if we have the file
    #             file_path = os.path.join(self.shared_files_path, filename)
    #             if not os.path.isfile(file_path):
    #                 logger.error(f" File '{filename}' not found in shared directory")
    #                 # Send error response
    #                 error_response = {
    #                     'type': MessageType.ERROR.name,
    #                     'message': f"File '{filename}' not found"
    #                 }
    #                 self.send_data(client_socket, json.dumps(error_response))
    #                 return
    #
    #             # Read file data
    #             logger.info(" Reading file from shared directory")
    #             with open(file_path, 'rb') as f:
    #                 file_data = f.read()
    #             logger.info(f" Read file: {len(file_data)} bytes")
    #
    #             # Calculate file hash before encryption for integrity verification
    #             logger.info("-" * 50)
    #             logger.info(" GENERATING FILE INTEGRITY HASH")
    #             file_hash = FileIntegrity.calculate_hash(file_data)
    #             logger.info(" Generated SHA-256 hash for integrity verification")
    #
    #             # --- Phase 3: Diffie-Hellman Key Exchange ---
    #             logger.info("-" * 50)
    #             logger.info(" HANDLING DIFFIE-HELLMAN KEY EXCHANGE (SENDER)")
    #
    #             # Receive DH initialization from client
    #             logger.info(" Waiting for requester's public key...")
    #             dh_data = self.receive_data(client_socket)
    #             if not dh_data:
    #                 logger.error(" No DH initialization received")
    #                 return
    #
    #             dh_init = json.loads(dh_data.decode('utf-8'))
    #             if dh_init['type'] != MessageType.DH_INIT.name:
    #                 logger.error(f" Unexpected message type: {dh_init['type']}")
    #                 return
    #
    #             logger.info(" Received requester's public key")
    #
    #             # Initialize our DH
    #             logger.info(" Initializing our Diffie-Hellman key exchange")
    #             dh = DiffieHellman()
    #
    #             # Get peer's public key
    #             other_public_key = dh_init['public_key']
    #
    #             # Send our public key
    #             dh_response = {
    #                 'type': MessageType.DH_RESPONSE.name,
    #                 'public_key': dh.get_public_key()
    #             }
    #             self.send_data(client_socket, json.dumps(dh_response))
    #             logger.info(" Sent our public key to requester")
    #
    #             # Compute shared key
    #             shared_key = dh.compute_shared_key(other_public_key)
    #             logger.info(" Successfully computed shared encryption key")
    #             logger.info(" DIFFIE-HELLMAN KEY EXCHANGE COMPLETED")
    #
    #             # Send file hash for integrity verification
    #             logger.info("-" * 50)
    #             logger.info(" SENDING FILE INTEGRITY HASH")
    #             hash_message = {
    #                 'type': MessageType.FILE_HASH.name,
    #                 'hash': file_hash.hex()
    #             }
    #             self.send_data(client_socket, json.dumps(hash_message))
    #             logger.info(" Sent file hash for integrity verification")
    #
    #             # Encrypt the file
    #             logger.info("-" * 50)
    #             logger.info(" ENCRYPTING FILE")
    #             iv, encrypted_data = FileEncryption.encrypt_file(file_data, shared_key)
    #             logger.info(f" Encrypted file: {len(file_data)} bytes → {len(encrypted_data)} bytes")
    #
    #             # Send encrypted file data with IV
    #             logger.info("-" * 50)
    #             logger.info(" SENDING ENCRYPTED FILE")
    #
    #             # Format: [IV (16 bytes)][Encrypted Data]
    #             transfer_data = iv + encrypted_data
    #
    #             # Send with length prefix
    #             logger.info(f" Sending {len(transfer_data)} bytes (IV + encrypted data)")
    #             client_socket.sendall(len(transfer_data).to_bytes(4, byteorder='big'))
    #             client_socket.sendall(transfer_data)
    #
    #             logger.info(" File transfer complete")
    #             logger.info("=" * 60)
    #             logger.info(" SECURE FILE TRANSFER COMPLETED SUCCESSFULLY")
    #             logger.info("=" * 60)
    #
    #         elif request['type'] == MessageType.FILE_INFO.name:
    #             # This is a notification from the server about an upcoming file transfer
    #             requester_ip = request['requester_ip']
    #             requester_port = request['requester_port']
    #             requester_username = request['requester_username']
    #             filename = request['filename']
    #
    #             logger.info(f" File request notification: {requester_username} at {requester_ip}:{requester_port} will download '{filename}'")
    #
    #             # Send acknowledgment
    #             ack_response = {
    #                 'type': MessageType.SUCCESS.name,
    #                 'message': "Notification received"
    #             }
    #             self.send_data(client_socket, json.dumps(ack_response))
    #             logger.info(" Sent acknowledgment to server")
    #
    #     except Exception as e:
    #         logger.error(f" File transfer error: {e}")
    #         try:
    #             # Try to send error response
    #             error_response = {
    #                 'type': MessageType.ERROR.name,
    #                 'message': f"Transfer error: {str(e)}"
    #             }
    #             self.send_data(client_socket, json.dumps(error_response))
    #         except:
    #             pass
    #     finally:
    #         client_socket.close()
    #         logger.info(f" Closed connection with {client_address}")

    def handle_file_transfer(self, client_socket, client_address):
        """Handle file transfer request from another client (with encryption and integrity verification)"""
        try:
            logger.info("=" * 60)
            logger.info(" HANDLING INCOMING FILE TRANSFER REQUEST")
            logger.info("=" * 60)
            logger.info(f" Received connection from {client_address}")

            # Receive request
            data = self.receive_data(client_socket)
            if not data:
                logger.error(" No data received in file transfer request")
                return

            request = json.loads(data.decode('utf-8'))
            logger.info(f" Received request of type: {request['type']}")

            if request['type'] == MessageType.FILE_TRANSFER.name:
                filename = request['filename']
                requester_username = request['requester_username']
                logger.info(f" File transfer request for '{filename}' from {requester_username}")

                # Check file existence
                file_path = os.path.join(self.shared_files_path, filename)
                if not os.path.isfile(file_path):
                    logger.error(f" File '{filename}' not found")
                    self.send_data(client_socket, json.dumps({
                        'type': MessageType.ERROR.name,
                        'message': f"File '{filename}' not found"
                    }))
                    return

                #  DECRYPT FILE AT REST
                logger.info("-" * 50)
                logger.info("  Decrypting file from disk (encrypted at rest)")
                with open(file_path, 'rb') as f:
                    raw = f.read()
                    salt, iv, ciphertext = raw[:16], raw[16:32], raw[32:]
                logger.info(" Extracted salt, IV, and ciphertext from disk")

                #Derive encryption key from password
                with open(self._creds_file) as f:
                    creds = json.load(f)
                password = self._enc.decrypt_data(creds['password'])  # Decrypt stored encrypted password
                key = derive_key(password, salt)
                logger.info(" Derived AES encryption key using PBKDF2 with salt from disk")

                # Decrypt file data for transfer
                try:
                    file_data = FileEncryption.decrypt_file(ciphertext, iv, key)
                    logger.info(" Successfully decrypted file from disk")
                except Exception as e:
                    logger.error(f" File decryption failed: {e}")
                    self.send_data(client_socket, json.dumps({
                        'type': MessageType.ERROR.name,
                        'message': "Decryption error before transfer"
                    }))
                    return

                #  FILE HASH FOR INTEGRITY
                logger.info("-" * 50)
                logger.info(" GENERATING FILE INTEGRITY HASH")
                file_hash = FileIntegrity.calculate_hash(file_data)
                logger.info(" Generated SHA-256 hash")

                #  DH KEY EXCHANGE
                logger.info("-" * 50)
                logger.info(" INITIATING DIFFIE-HELLMAN KEY EXCHANGE")
                dh_data = self.receive_data(client_socket)
                if not dh_data:
                    logger.error(" No DH key received")
                    return
                dh_init = json.loads(dh_data.decode('utf-8'))
                if dh_init['type'] != MessageType.DH_INIT.name:
                    logger.error(" Invalid DH message")
                    return

                other_public_key = dh_init['public_key']
                dh = DiffieHellman()
                shared_key = dh.compute_shared_key(other_public_key)
                logger.info(" Computed shared DH session key")

                dh_response = {
                    'type': MessageType.DH_RESPONSE.name,
                    'public_key': dh.get_public_key()
                }
                self.send_data(client_socket, json.dumps(dh_response))
                logger.info(" Sent our DH public key")

                # Send file hash
                logger.info("-" * 50)
                logger.info(" SENDING FILE HASH")
                self.send_data(client_socket, json.dumps({
                    'type': MessageType.FILE_HASH.name,
                    'hash': file_hash.hex()
                }))
                logger.info(" Sent file hash")

                # ENCRYPT FOR TRANSIT
                logger.info("-" * 50)
                logger.info(" Re-encrypting file with DH session key for transit")
                iv, encrypted_data = FileEncryption.encrypt_file(file_data, shared_key)
                logger.info(f" Re-encrypted file with DH key (length: {len(encrypted_data)} bytes)")

                # Send encrypted file
                logger.info("-" * 50)
                logger.info(" SENDING ENCRYPTED FILE")
                transfer_data = iv + encrypted_data
                client_socket.sendall(len(transfer_data).to_bytes(4, byteorder='big'))
                client_socket.sendall(transfer_data)
                logger.info(" File securely sent")

                logger.info("=" * 60)
                logger.info(" SECURE FILE TRANSFER COMPLETE")
                logger.info("=" * 60)

            elif request['type'] == MessageType.FILE_INFO.name:
                logger.info(f" File info request for upcoming transfer: {request}")
                self.send_data(client_socket, json.dumps({
                    'type': MessageType.SUCCESS.name,
                    'message': "Notification received"
                }))
                logger.info(" Sent acknowledgment")

        except Exception as e:
            logger.error(f" Transfer error: {e}")
            try:
                self.send_data(client_socket, json.dumps({
                    'type': MessageType.ERROR.name,
                    'message': f"Transfer error: {str(e)}"
                }))
            except:
                pass
        finally:
            client_socket.close()
            logger.info(f" Closed connection with {client_address}")

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

    def receive_file(self, sock):
        """Receive file data from socket"""
        try:
            # First receive the length of the file
            length_bytes = sock.recv(4)
            if not length_bytes:
                return None

            file_length = int.from_bytes(length_bytes, byteorder='big')

            # Receive the file data
            chunks = []
            bytes_received = 0

            while bytes_received < file_length:
                chunk = sock.recv(min(4096, file_length - bytes_received))
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
