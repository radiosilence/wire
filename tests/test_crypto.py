import pytest
from datetime import datetime, timezone

from wire.crypto import (
    SymmetricEncryption,
    AsymmetricEncryption,
    KeyDerivation,
    MessageSigner,
    SecureRandom,
    EncryptedMessage,
    encrypt_message,
    decrypt_message,
    hash_password,
    verify_password,
    EncryptionError,
    DecryptionError,
    KeyDerivationError,
)


class TestKeyDerivation:
    """Test key derivation functions."""
    
    def test_pbkdf2_key_derivation(self):
        """Test PBKDF2 key derivation."""
        password = "test_password_123"
        salt = KeyDerivation.generate_salt()
        
        # Derive key
        key = KeyDerivation.derive_key_pbkdf2(password, salt)
        
        assert len(key) == 32  # Default key length
        assert isinstance(key, bytes)
        
        # Same password and salt should produce same key
        key2 = KeyDerivation.derive_key_pbkdf2(password, salt)
        assert key == key2
        
        # Different salt should produce different key
        salt2 = KeyDerivation.generate_salt()
        key3 = KeyDerivation.derive_key_pbkdf2(password, salt2)
        assert key != key3
    
    def test_scrypt_key_derivation(self):
        """Test Scrypt key derivation."""
        password = "test_password_123"
        salt = KeyDerivation.generate_salt()
        
        # Derive key with lower parameters for testing
        key = KeyDerivation.derive_key_scrypt(
            password, salt, n=2**14, r=8, p=1
        )
        
        assert len(key) == 32
        assert isinstance(key, bytes)
        
        # Same inputs should produce same key
        key2 = KeyDerivation.derive_key_scrypt(
            password, salt, n=2**14, r=8, p=1
        )
        assert key == key2
    
    def test_salt_generation(self):
        """Test salt generation."""
        salt1 = KeyDerivation.generate_salt()
        salt2 = KeyDerivation.generate_salt()
        
        assert len(salt1) == 32  # Default salt length
        assert salt1 != salt2  # Should be random
        
        # Custom length
        salt3 = KeyDerivation.generate_salt(16)
        assert len(salt3) == 16


class TestSymmetricEncryption:
    """Test symmetric encryption."""
    
    @pytest.mark.parametrize("algorithm", ["AES-256-GCM", "ChaCha20-Poly1305"])
    def test_encrypt_decrypt(self, algorithm):
        """Test basic encryption and decryption."""
        crypto = SymmetricEncryption(algorithm)
        key = crypto.generate_key()
        plaintext = "Hello, Wire! 🔐"
        
        # Encrypt
        encrypted = crypto.encrypt(plaintext, key)
        
        assert isinstance(encrypted, EncryptedMessage)
        assert encrypted.algorithm == algorithm
        assert encrypted.ciphertext != plaintext.encode()
        
        # Decrypt
        decrypted = crypto.decrypt(encrypted, key)
        assert decrypted.decode("utf-8") == plaintext
    
    def test_encrypt_with_associated_data(self):
        """Test encryption with associated data."""
        crypto = SymmetricEncryption()
        key = crypto.generate_key()
        plaintext = "Secret message"
        associated_data = b"metadata"
        
        # Encrypt with associated data
        encrypted = crypto.encrypt(plaintext, key, associated_data=associated_data)
        
        # Decrypt with same associated data should work
        decrypted = crypto.decrypt(encrypted, key, associated_data=associated_data)
        assert decrypted.decode("utf-8") == plaintext
        
        # Decrypt with different associated data should fail
        with pytest.raises(DecryptionError):
            crypto.decrypt(encrypted, key, associated_data=b"wrong_metadata")
    
    def test_password_based_encryption(self):
        """Test password-based encryption."""
        crypto = SymmetricEncryption()
        password = "strong_password_123!"
        plaintext = "Secret data"
        
        # Encrypt with password
        encrypted = crypto.encrypt_with_password(plaintext, password, kdf="scrypt")
        
        assert encrypted.salt is not None
        assert len(encrypted.salt) == 32
        
        # Decrypt with same password
        decrypted = crypto.decrypt_with_password(encrypted, password, kdf="scrypt")
        assert decrypted.decode("utf-8") == plaintext
        
        # Wrong password should fail
        with pytest.raises(DecryptionError):
            crypto.decrypt_with_password(encrypted, "wrong_password", kdf="scrypt")
    
    def test_nonce_generation(self):
        """Test nonce generation and uniqueness."""
        crypto = SymmetricEncryption()
        nonces = set()
        
        # Generate multiple nonces
        for _ in range(100):
            nonce = crypto.generate_nonce()
            assert len(nonce) == 12  # Default nonce length
            nonces.add(nonce)
        
        # All should be unique
        assert len(nonces) == 100


class TestEncryptedMessage:
    """Test EncryptedMessage serialization."""
    
    def test_to_from_bytes(self):
        """Test serialization to/from bytes."""
        message = EncryptedMessage(
            ciphertext=b"encrypted_data",
            nonce=b"twelve_bytes",
            salt=b"thirty_two_bytes_salt_here_12345",
            algorithm="AES-256-GCM"
        )
        
        # Serialize
        data = message.to_bytes()
        assert isinstance(data, bytes)
        
        # Deserialize
        restored = EncryptedMessage.from_bytes(data)
        
        assert restored.ciphertext == message.ciphertext
        assert restored.nonce == message.nonce
        assert restored.salt == message.salt
        assert restored.algorithm == message.algorithm
    
    def test_to_from_base64(self):
        """Test base64 encoding/decoding."""
        message = EncryptedMessage(
            ciphertext=b"encrypted_data",
            nonce=b"twelve_bytes",
            algorithm="ChaCha20-Poly1305"
        )
        
        # Encode
        b64 = message.to_base64()
        assert isinstance(b64, str)
        
        # Decode
        restored = EncryptedMessage.from_base64(b64)
        
        assert restored.ciphertext == message.ciphertext
        assert restored.nonce == message.nonce
        assert restored.salt is None
        assert restored.algorithm == message.algorithm
    
    def test_timestamp(self):
        """Test automatic timestamp."""
        message = EncryptedMessage(
            ciphertext=b"data",
            nonce=b"nonce"
        )
        
        assert message.timestamp is not None
        assert isinstance(message.timestamp, datetime)
        assert message.timestamp.tzinfo is not None


class TestAsymmetricEncryption:
    """Test asymmetric encryption."""
    
    def test_keypair_generation(self):
        """Test EC keypair generation."""
        crypto = AsymmetricEncryption()
        private_key, public_key = crypto.generate_keypair()
        
        assert private_key is not None
        assert public_key is not None
        
        # Keys should be different
        private_key2, public_key2 = crypto.generate_keypair()
        assert private_key != private_key2
        assert public_key != public_key2
    
    def test_shared_secret_derivation(self):
        """Test ECDH shared secret derivation."""
        crypto = AsymmetricEncryption()
        
        # Alice's keypair
        alice_private, alice_public = crypto.generate_keypair()
        
        # Bob's keypair
        bob_private, bob_public = crypto.generate_keypair()
        
        # Derive shared secrets
        alice_shared = crypto.derive_shared_secret(alice_private, bob_public)
        bob_shared = crypto.derive_shared_secret(bob_private, alice_public)
        
        # Both should derive the same secret
        assert alice_shared == bob_shared
        assert len(alice_shared) == 32  # HKDF output
    
    def test_key_serialization(self):
        """Test key serialization/deserialization."""
        crypto = AsymmetricEncryption()
        private_key, public_key = crypto.generate_keypair()
        
        # Serialize without password
        private_pem = crypto.serialize_private_key(private_key)
        public_pem = crypto.serialize_public_key(public_key)
        
        assert b"BEGIN PRIVATE KEY" in private_pem
        assert b"BEGIN PUBLIC KEY" in public_pem
        
        # Load keys
        loaded_private = crypto.load_private_key(private_pem)
        loaded_public = crypto.load_public_key(public_pem)
        
        # Verify they work the same
        test_private, test_public = crypto.generate_keypair()
        secret1 = crypto.derive_shared_secret(loaded_private, test_public)
        secret2 = crypto.derive_shared_secret(test_private, loaded_public)
        
        # Original keys should produce same secrets
        secret3 = crypto.derive_shared_secret(private_key, test_public)
        secret4 = crypto.derive_shared_secret(test_private, public_key)
        
        assert secret1 == secret3
        assert secret2 == secret4
    
    def test_key_serialization_with_password(self):
        """Test password-protected key serialization."""
        crypto = AsymmetricEncryption()
        private_key, _ = crypto.generate_keypair()
        password = "key_password_123"
        
        # Serialize with password
        private_pem = crypto.serialize_private_key(private_key, password)
        assert b"ENCRYPTED" in private_pem
        
        # Load with correct password
        loaded = crypto.load_private_key(private_pem, password)
        assert loaded is not None
        
        # Wrong password should fail
        with pytest.raises(Exception):
            crypto.load_private_key(private_pem, "wrong_password")


class TestMessageSigner:
    """Test message signing."""
    
    def test_sign_verify(self):
        """Test message signing and verification."""
        signer = MessageSigner()
        crypto = AsymmetricEncryption()
        private_key, public_key = crypto.generate_keypair()
        
        message = "Important message"
        
        # Sign
        signature = signer.sign(message, private_key)
        assert isinstance(signature, bytes)
        assert len(signature) > 0
        
        # Verify with correct key
        assert signer.verify(message, signature, public_key) is True
        
        # Verify with wrong message should fail
        assert signer.verify("Different message", signature, public_key) is False
        
        # Verify with wrong key should fail
        _, wrong_public = crypto.generate_keypair()
        assert signer.verify(message, signature, wrong_public) is False
    
    def test_sign_bytes(self):
        """Test signing byte messages."""
        signer = MessageSigner()
        crypto = AsymmetricEncryption()
        private_key, public_key = crypto.generate_keypair()
        
        message = b"Binary data \x00\x01\x02"
        
        signature = signer.sign(message, private_key)
        assert signer.verify(message, signature, public_key) is True


class TestSecureRandom:
    """Test secure random generation."""
    
    def test_generate_token(self):
        """Test token generation."""
        token1 = SecureRandom.generate_token()
        token2 = SecureRandom.generate_token()
        
        assert len(token1) > 32  # URL-safe encoding makes it longer
        assert token1 != token2
        assert isinstance(token1, str)
        
        # Custom length
        token3 = SecureRandom.generate_token(16)
        assert len(token3) > 16
    
    def test_generate_hex(self):
        """Test hex string generation."""
        hex1 = SecureRandom.generate_hex()
        hex2 = SecureRandom.generate_hex()
        
        assert len(hex1) == 64  # 32 bytes = 64 hex chars
        assert hex1 != hex2
        assert all(c in "0123456789abcdef" for c in hex1)
        
        # Custom length
        hex3 = SecureRandom.generate_hex(16)
        assert len(hex3) == 32
    
    def test_generate_bytes(self):
        """Test random bytes generation."""
        bytes1 = SecureRandom.generate_bytes()
        bytes2 = SecureRandom.generate_bytes()
        
        assert len(bytes1) == 32
        assert bytes1 != bytes2
        assert isinstance(bytes1, bytes)
    
    def test_generate_int(self):
        """Test random integer generation."""
        # Test range
        for _ in range(100):
            num = SecureRandom.generate_int(10, 20)
            assert 10 <= num < 20
        
        # Test uniqueness
        numbers = set()
        for _ in range(100):
            numbers.add(SecureRandom.generate_int(0, 1000000))
        
        assert len(numbers) > 90  # Should be mostly unique


class TestConvenienceFunctions:
    """Test convenience functions."""
    
    def test_encrypt_decrypt_message(self):
        """Test simple message encryption/decryption."""
        key = SymmetricEncryption().generate_key()
        plaintext = "Hello, Wire!"
        
        # Encrypt
        encrypted = encrypt_message(plaintext, key)
        assert isinstance(encrypted, str)
        assert encrypted != plaintext
        
        # Decrypt
        decrypted = decrypt_message(encrypted, key)
        assert decrypted == plaintext
    
    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "secure_password_123!"
        
        # Hash password
        hashed = hash_password(password)
        assert isinstance(hashed, str)
        assert hashed.startswith("scrypt$")
        assert len(hashed.split("$")) == 3
        
        # Verify correct password
        assert verify_password(password, hashed) is True
        
        # Verify wrong password
        assert verify_password("wrong_password", hashed) is False
        
        # Different hashes for same password
        hashed2 = hash_password(password)
        assert hashed != hashed2
        assert verify_password(password, hashed2) is True