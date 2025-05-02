"""
Enhanced Cryptographic utilities for CipherShare Phase 3 implementation
Includes:
- Diffie-Hellman key exchange
- AES encryption and decryption
- File integrity verification with SHA-256
"""

import os
import hashlib
import secrets
import base64
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Get the logger
logger = logging.getLogger("CipherShare Client")

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
        
        logger.info(" Initializing Diffie-Hellman with 1024-bit parameters")
        logger.debug(f"DH Parameters: g={self.g}, p=<1024-bit prime>")
        
        # Generate private key (a random integer between 1 and p-1)
        self.private_key = secrets.randbelow(self.p - 1) + 1
        logger.info(" Generated private key (random number)")
        
        # Calculate public key: g^private_key mod p
        self.public_key = pow(self.g, self.private_key, self.p)
        logger.info(" Calculated public key using formula: g^private_key mod p")
        logger.debug(f"Public key: {self.public_key % 1000}... (showing last 3 digits)")
        
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
        logger.info(" Beginning shared key computation")
        logger.info(f" Using peer's public key: {other_public_key % 1000}... (showing last 3 digits)")
        
        # Compute shared secret: other_public_key^private_key mod p
        shared_secret = pow(other_public_key, self.private_key, self.p)
        logger.info(" Computed raw shared secret using formula: peer_public_key^private_key mod p")
        logger.debug(f"Raw shared secret: {shared_secret % 1000}... (showing last 3 digits)")
        
        # Derive a 32-byte key using SHA-256
        shared_key = hashlib.sha256(str(shared_secret).encode()).digest()
        logger.info(" Derived 256-bit encryption key using SHA-256 hash of shared secret")
        logger.debug(f"First 4 bytes of shared key: {shared_key[:4].hex()}")
        
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
        logger.info(" Beginning file encryption with AES-256-CBC")
        logger.info(f" Original file size: {len(file_data)} bytes")
        
        # Generate a random IV
        iv = os.urandom(16)
        logger.info(" Generated random 16-byte Initialization Vector (IV)")
        logger.debug(f"IV: {iv.hex()}")
        
        # Pad the data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(file_data) + padder.finalize()
        logger.info(f" Applied PKCS7 padding to data (padded size: {len(padded_data)} bytes)")
        
        # Create encryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        logger.info(" Created AES-256-CBC encryptor with the shared key")
        
        # Encrypt data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        logger.info(f" Encrypted file data (encrypted size: {len(encrypted_data)} bytes)")
        logger.debug(f"First 16 bytes of encrypted data: {encrypted_data[:16].hex()}")
        
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
        logger.info(" Beginning file decryption with AES-256-CBC")
        logger.info(f" Encrypted file size: {len(encrypted_data)} bytes")
        logger.debug(f"IV: {iv.hex()}")
        
        # Create decryptor
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        logger.info(" Created AES-256-CBC decryptor with the shared key")
        
        # Decrypt data
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        logger.info(f" Decrypted to padded data (padded size: {len(padded_data)} bytes)")
        
        # Unpad the data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        file_data = unpadder.update(padded_data) + unpadder.finalize()
        logger.info(f" Removed PKCS7 padding from data (final size: {len(file_data)} bytes)")
        
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
        logger.info(" Calculating SHA-256 hash for file integrity")
        file_hash = hashlib.sha256(file_data).digest()
        logger.info(" Generated SHA-256 hash of file")
        logger.debug(f"Hash value: {file_hash.hex()}")
        return file_hash
    
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
        logger.info(" Verifying file integrity with SHA-256 hash")
        actual_hash = FileIntegrity.calculate_hash(file_data)
        
        # Use constant-time comparison to prevent timing attacks
        match = secrets.compare_digest(actual_hash, expected_hash)
        
        if match:
            logger.info(" INTEGRITY VERIFIED: File hash matches expected value")
        else:
            logger.error(" INTEGRITY FAILURE: File hash does not match expected value")
            logger.debug(f"Expected hash: {expected_hash.hex()}")
            logger.debug(f"Actual hash: {actual_hash.hex()}")
        
        return match