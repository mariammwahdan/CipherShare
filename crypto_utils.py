"""
Cryptographic utilities for CipherShare Phase 3 implementation
Includes:
- Diffie-Hellman key exchange
- AES encryption and decryption
- File integrity verification with SHA-256
"""

import os
import hashlib
import secrets
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# -----------------------------------------------------------------------------
# Diffie-Hellman Key Exchange
# -----------------------------------------------------------------------------

class DiffieHellman:
    """Implements Diffie-Hellman key exchange protocol"""
    
    def __init__(self):
        # Generate parameters (p, g)
        self.parameters = dh.generate_parameters(generator=2, key_size=2048, 
                                                backend=default_backend())
        # Generate private key
        self.private_key = self.parameters.generate_private_key()
        # Get public key
        self.public_key = self.private_key.public_key()
        # Public parameters
        self.p = self.parameters.parameter_numbers().p
        self.g = self.parameters.parameter_numbers().g
        # Shared key - will be computed later
        self.shared_key = None
        
    def get_public_params(self):
        """Return public parameters (p, g)"""
        return {
            'p': self.p,
            'g': self.g
        }
    
    def get_public_key(self):
        """Return public key"""
        return self.public_key.public_numbers().y
    
    def compute_shared_key(self, other_public_key):
        """Compute shared key using the other party's public key"""
        # Convert the integer public key to a DHPublicKey object
        peer_public_numbers = dh.DHPublicNumbers(other_public_key, 
                                                self.parameters.parameter_numbers())
        peer_public_key = peer_public_numbers.public_key(default_backend())
        
        # Compute shared key
        shared_key = self.private_key.exchange(peer_public_key)
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=None,
            info=b'ciphershare-key',
            backend=default_backend()
        ).derive(shared_key)
        
        self.shared_key = derived_key
        return derived_key

# -----------------------------------------------------------------------------
# File Encryption and Decryption
# -----------------------------------------------------------------------------

class FileEncryption:
    """Implements file encryption and decryption using AES"""
    
    @staticmethod
    def encrypt_file(file_data, key):
        """
        Encrypt file data using AES-256-CBC.
        
        Args:
            file_data (bytes): Raw file data to encrypt
            key (bytes): 32-byte encryption key (256 bits)
            
        Returns:
            tuple: (iv, encrypted_data)
        """
        # Generate a random IV
        iv = os.urandom(16)
        
        # Pad the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        
        # Create encryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return iv, encrypted_data
    
    @staticmethod
    def decrypt_file(encrypted_data, iv, key):
        """
        Decrypt file data using AES-256-CBC.
        
        Args:
            encrypted_data (bytes): Encrypted file data
            iv (bytes): 16-byte initialization vector
            key (bytes): 32-byte encryption key (256 bits)
            
        Returns:
            bytes: Decrypted file data
        """
        # Create decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        # Decrypt data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        file_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return file_data

# -----------------------------------------------------------------------------
# File Integrity Verification
# -----------------------------------------------------------------------------

class FileIntegrity:
    """Implements file integrity verification using SHA-256"""
    
    @staticmethod
    def calculate_hash(file_data):
        """
        Calculate SHA-256 hash of file data.
        
        Args:
            file_data (bytes): File data to hash
            
        Returns:
            bytes: SHA-256 hash of the file
        """
        return hashlib.sha256(file_data).digest()
    
    @staticmethod
    def verify_hash(file_data, expected_hash):
        """
        Verify file integrity by comparing hash.
        
        Args:
            file_data (bytes): File data to verify
            expected_hash (bytes): Expected SHA-256 hash
            
        Returns:
            bool: True if hash matches, False otherwise
        """
        actual_hash = FileIntegrity.calculate_hash(file_data)
        return secrets.compare_digest(actual_hash, expected_hash)