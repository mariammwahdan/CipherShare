import os
import pytest
from simplified_crypto_utils import DiffieHellman, derive_key, FileEncryption, FileIntegrity


def test_diffie_hellman_shared_key():
    # Create two DiffieHellman instances for two parties
    alice = DiffieHellman()
    bob = DiffieHellman()

    # Exchange public keys and compute shared keys
    alice_shared = alice.compute_shared_key(bob.get_public_key())
    bob_shared = bob.compute_shared_key(alice.get_public_key())

    # Both should derive the same shared key
    assert isinstance(alice_shared, bytes)
    assert isinstance(bob_shared, bytes)
    assert alice_shared == bob_shared
    assert len(alice_shared) == 32  # 256-bit key
def test_derive_key_consistency_and_salt_behavior():
    password = "strongpassword"
    salt = os.urandom(16)

    # Derive key twice with same password and salt
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)

    # Keys should be consistent
    assert key1 == key2

    # Different salt yields different key
    another_salt = os.urandom(16)
    key3 = derive_key(password, another_salt)
    assert key3 != key1


def test_encrypt_decrypt_file_roundtrip():
    # Prepare random file data and a random key
    original_data = os.urandom(128)  # 128 bytes of data
    key = os.urandom(32)  # AES-256 key

    # Encrypt the data
    iv, encrypted = FileEncryption.encrypt_file(original_data, key)
    assert isinstance(iv, bytes) and len(iv) == 16
    assert isinstance(encrypted, bytes)

    # Decrypt the data and verify equality
    decrypted = FileEncryption.decrypt_file(encrypted, iv, key)
    assert decrypted == original_data


def test_file_integrity_hash_and_verify():
    data = b"Sample file content for hashing"
    # Calculate hash
    file_hash = FileIntegrity.calculate_hash(data)
    assert isinstance(file_hash, bytes)
    assert len(file_hash) == 32  # SHA-256 produces 32 bytes

    # Verification should succeed for correct data
    assert FileIntegrity.verify_hash(data, file_hash)

    # Verification should fail for tampered data
    tampered = data + b"tamper"
    assert not FileIntegrity.verify_hash(tampered, file_hash)


if __name__ == "__main__":
    pytest.main()
