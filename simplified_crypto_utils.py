"""
Simplified Cryptographic utilities for CipherShare Phase 3 implementation
Includes:
- Diffie-Hellman key exchange
- AES encryption and decryption
- File integrity verification with SHA-256
"""

import os
import hashlib
import secrets
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# -----------------------------------------------------------------------------
# Simplified Diffie-Hellman Key Exchange
# -----------------------------------------------------------------------------

class DiffieHellman:
    """Implements a simplified Diffie-Hellman key exchange protocol"""
    
    # Fixed parameters - these would typically be generated, but we use fixed ones for simplicity
    # These are 1024-bit parameters
    DEFAULT_P = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
    DEFAULT_G = 2
    
    def __init__(self):
        # Use fixed parameters for simplicity
        self.p = self.DEFAULT_P
        self.g = self.DEFAULT_G
        
        # Generate private key (a random integer between 1 and p-1)
        self.private_key = secrets.randbelow(self.p - 1) + 1
        
        # Calculate public key: g^private_key mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        
        # Shared key will be computed later
        self.shared_key = None
    
    def get_public_params(self):
        """Return public parameters (p, g)"""
        return {
            'p': self.p,
            'g': self.g
        }
    
    def get_public_key(self):
        """Return public key"""
        return self.public_key
    
    def compute_shared_key(self, other_public_key):
        """Compute shared key using the other party's public key"""
        # Compute shared secret: other_public_key^private_key mod p
        shared_secret = pow(other_public_key, self.private_key, self.p)
        
        # Derive a 32-byte key using SHA-256
        shared_key = hashlib.sha256(str(shared_secret).encode()).digest()
        
        self.shared_key = shared_key
        return shared_key

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