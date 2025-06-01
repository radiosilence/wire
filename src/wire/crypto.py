from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Protocol, TypeAlias

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import (
    PrivateKeyTypes,
    PublicKeyTypes,
)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryptionAvailable,
    PrivateFormat,
    PublicFormat,
)
from cryptography.x509 import load_pem_x509_certificate

# Type aliases
Salt: TypeAlias = bytes
Nonce: TypeAlias = bytes
Key: TypeAlias = bytes
EncryptedData: TypeAlias = bytes
PlainData: TypeAlias = bytes
Signature: TypeAlias = bytes

# Constants
DEFAULT_SALT_LENGTH = 32
DEFAULT_KEY_LENGTH = 32
DEFAULT_NONCE_LENGTH = 12
DEFAULT_TAG_LENGTH = 16
DEFAULT_KDF_ITERATIONS = 600_000
DEFAULT_SCRYPT_N = 2**17
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1


class CryptoError(Exception):
    """Base exception for cryptography errors."""
    pass


class EncryptionError(CryptoError):
    """Raised when encryption fails."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails."""
    pass


class KeyDerivationError(CryptoError):
    """Raised when key derivation fails."""
    pass


class SignatureError(CryptoError):
    """Raised when signature verification fails."""
    pass


@dataclass(frozen=True)
class EncryptedMessage:
    """Container for encrypted message data."""
    
    ciphertext: EncryptedData
    nonce: Nonce
    salt: Salt | None = None
    algorithm: str = "AES-256-GCM"
    timestamp: datetime = None
    
    def __post_init__(self) -> None:
        if self.timestamp is None:
            object.__setattr__(self, "timestamp", datetime.now(timezone.utc))
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes for storage/transmission."""
        # Format: algorithm(1) | salt_len(1) | nonce_len(1) | salt | nonce | ciphertext
        salt_bytes = self.salt or b""
        salt_len = len(salt_bytes)
        nonce_len = len(self.nonce)
        
        algo_byte = b"\x01" if self.algorithm == "AES-256-GCM" else b"\x02"
        
        return (
            algo_byte +
            salt_len.to_bytes(1, "big") +
            nonce_len.to_bytes(1, "big") +
            salt_bytes +
            self.nonce +
            self.ciphertext
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedMessage:
        """Deserialize from bytes."""
        if len(data) < 3:
            raise ValueError("Invalid encrypted message format")
        
        algo_byte = data[0]
        salt_len = data[1]
        nonce_len = data[2]
        
        if len(data) < 3 + salt_len + nonce_len:
            raise ValueError("Invalid encrypted message length")
        
        algorithm = "AES-256-GCM" if algo_byte == 1 else "ChaCha20-Poly1305"
        
        salt = data[3:3+salt_len] if salt_len > 0 else None
        nonce = data[3+salt_len:3+salt_len+nonce_len]
        ciphertext = data[3+salt_len+nonce_len:]
        
        return cls(
            ciphertext=ciphertext,
            nonce=nonce,
            salt=salt,
            algorithm=algorithm
        )
    
    def to_base64(self) -> str:
        """Encode as base64 string."""
        return base64.urlsafe_b64encode(self.to_bytes()).decode("utf-8")
    
    @classmethod
    def from_base64(cls, data: str) -> EncryptedMessage:
        """Decode from base64 string."""
        return cls.from_bytes(base64.urlsafe_b64decode(data))


class KeyDerivation:
    """Key derivation functions for password-based encryption."""
    
    @staticmethod
    def derive_key_pbkdf2(
        password: str | bytes,
        salt: Salt,
        iterations: int = DEFAULT_KDF_ITERATIONS,
        key_length: int = DEFAULT_KEY_LENGTH,
    ) -> Key:
        """Derive a key using PBKDF2-HMAC-SHA256."""
        if isinstance(password, str):
            password = password.encode("utf-8")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        
        try:
            return kdf.derive(password)
        except Exception as e:
            raise KeyDerivationError(f"PBKDF2 key derivation failed: {e}") from e
    
    @staticmethod
    def derive_key_scrypt(
        password: str | bytes,
        salt: Salt,
        n: int = DEFAULT_SCRYPT_N,
        r: int = DEFAULT_SCRYPT_R,
        p: int = DEFAULT_SCRYPT_P,
        key_length: int = DEFAULT_KEY_LENGTH,
    ) -> Key:
        """Derive a key using scrypt."""
        if isinstance(password, str):
            password = password.encode("utf-8")
        
        kdf = Scrypt(
            salt=salt,
            length=key_length,
            n=n,
            r=r,
            p=p,
            backend=default_backend(),
        )
        
        try:
            return kdf.derive(password)
        except Exception as e:
            raise KeyDerivationError(f"Scrypt key derivation failed: {e}") from e
    
    @staticmethod
    def generate_salt(length: int = DEFAULT_SALT_LENGTH) -> Salt:
        """Generate a random salt."""
        return secrets.token_bytes(length)


class SymmetricEncryption:
    """Symmetric encryption using AES-GCM or ChaCha20-Poly1305."""
    
    def __init__(
        self,
        algorithm: Literal["AES-256-GCM", "ChaCha20-Poly1305"] = "AES-256-GCM",
    ) -> None:
        self.algorithm = algorithm
        self._cipher = AESGCM if algorithm == "AES-256-GCM" else ChaCha20Poly1305
    
    def generate_key(self) -> Key:
        """Generate a random encryption key."""
        return secrets.token_bytes(DEFAULT_KEY_LENGTH)
    
    def generate_nonce(self) -> Nonce:
        """Generate a random nonce."""
        return secrets.token_bytes(DEFAULT_NONCE_LENGTH)
    
    def encrypt(
        self,
        plaintext: PlainData | str,
        key: Key,
        nonce: Nonce | None = None,
        associated_data: bytes | None = None,
    ) -> EncryptedMessage:
        """Encrypt data with authenticated encryption."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")
        
        if nonce is None:
            nonce = self.generate_nonce()
        
        try:
            cipher = self._cipher(key)
            ciphertext = cipher.encrypt(nonce, plaintext, associated_data)
            
            return EncryptedMessage(
                ciphertext=ciphertext,
                nonce=nonce,
                algorithm=self.algorithm,
            )
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    def decrypt(
        self,
        encrypted_message: EncryptedMessage,
        key: Key,
        associated_data: bytes | None = None,
    ) -> PlainData:
        """Decrypt data with authenticated encryption."""
        try:
            cipher = self._cipher(key)
            plaintext = cipher.decrypt(
                encrypted_message.nonce,
                encrypted_message.ciphertext,
                associated_data,
            )
            return plaintext
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    def encrypt_with_password(
        self,
        plaintext: PlainData | str,
        password: str,
        kdf: Literal["pbkdf2", "scrypt"] = "scrypt",
    ) -> EncryptedMessage:
        """Encrypt data using a password."""
        salt = KeyDerivation.generate_salt()
        
        if kdf == "pbkdf2":
            key = KeyDerivation.derive_key_pbkdf2(password, salt)
        else:
            key = KeyDerivation.derive_key_scrypt(password, salt)
        
        encrypted = self.encrypt(plaintext, key)
        
        return EncryptedMessage(
            ciphertext=encrypted.ciphertext,
            nonce=encrypted.nonce,
            salt=salt,
            algorithm=self.algorithm,
        )
    
    def decrypt_with_password(
        self,
        encrypted_message: EncryptedMessage,
        password: str,
        kdf: Literal["pbkdf2", "scrypt"] = "scrypt",
    ) -> PlainData:
        """Decrypt data using a password."""
        if encrypted_message.salt is None:
            raise DecryptionError("No salt provided for password-based decryption")
        
        if kdf == "pbkdf2":
            key = KeyDerivation.derive_key_pbkdf2(password, encrypted_message.salt)
        else:
            key = KeyDerivation.derive_key_scrypt(password, encrypted_message.salt)
        
        return self.decrypt(encrypted_message, key)


class AsymmetricEncryption:
    """Asymmetric encryption using elliptic curves."""
    
    def __init__(self, curve: ec.EllipticCurve = ec.SECP384R1()) -> None:
        self.curve = curve
    
    def generate_keypair(self) -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
        """Generate an EC key pair."""
        private_key = ec.generate_private_key(self.curve, default_backend())
        public_key = private_key.public_key()
        return private_key, public_key
    
    def derive_shared_secret(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        peer_public_key: ec.EllipticCurvePublicKey,
    ) -> bytes:
        """Derive a shared secret using ECDH."""
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Use HKDF to derive a proper encryption key
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"wire-encryption-key",
            backend=default_backend(),
        )
        
        return hkdf.derive(shared_key)
    
    def serialize_private_key(
        self,
        private_key: ec.EllipticCurvePrivateKey,
        password: str | None = None,
    ) -> bytes:
        """Serialize a private key to PEM format."""
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
        else:
            encryption = serialization.NoEncryption()
        
        return private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )
    
    def serialize_public_key(self, public_key: ec.EllipticCurvePublicKey) -> bytes:
        """Serialize a public key to PEM format."""
        return public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        )
    
    def load_private_key(
        self,
        key_data: bytes,
        password: str | None = None,
    ) -> ec.EllipticCurvePrivateKey:
        """Load a private key from PEM format."""
        return serialization.load_pem_private_key(
            key_data,
            password=password.encode("utf-8") if password else None,
            backend=default_backend(),
        )
    
    def load_public_key(self, key_data: bytes) -> ec.EllipticCurvePublicKey:
        """Load a public key from PEM format."""
        return serialization.load_pem_public_key(key_data, backend=default_backend())


class MessageSigner:
    """Digital signatures for message authentication."""
    
    def __init__(self) -> None:
        self.curve = ec.SECP384R1()
    
    def sign(
        self,
        message: bytes | str,
        private_key: ec.EllipticCurvePrivateKey,
    ) -> Signature:
        """Sign a message using ECDSA."""
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        return signature
    
    def verify(
        self,
        message: bytes | str,
        signature: Signature,
        public_key: ec.EllipticCurvePublicKey,
    ) -> bool:
        """Verify a message signature."""
        if isinstance(message, str):
            message = message.encode("utf-8")
        
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class SecureRandom:
    """Cryptographically secure random number generation."""
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate a URL-safe random token."""
        return secrets.token_urlsafe(length)
    
    @staticmethod
    def generate_hex(length: int = 32) -> str:
        """Generate a hex-encoded random string."""
        return secrets.token_hex(length)
    
    @staticmethod
    def generate_bytes(length: int = 32) -> bytes:
        """Generate random bytes."""
        return secrets.token_bytes(length)
    
    @staticmethod
    def generate_int(min_val: int = 0, max_val: int = 2**32 - 1) -> int:
        """Generate a random integer in range."""
        return secrets.randbelow(max_val - min_val) + min_val


# Convenience functions
def encrypt_message(plaintext: str, key: Key) -> str:
    """Encrypt a message and return base64-encoded result."""
    crypto = SymmetricEncryption()
    encrypted = crypto.encrypt(plaintext, key)
    return encrypted.to_base64()


def decrypt_message(encrypted_data: str, key: Key) -> str:
    """Decrypt a base64-encoded message."""
    crypto = SymmetricEncryption()
    encrypted = EncryptedMessage.from_base64(encrypted_data)
    plaintext = crypto.decrypt(encrypted, key)
    return plaintext.decode("utf-8")


def hash_password(password: str) -> str:
    """Hash a password for storage."""
    salt = KeyDerivation.generate_salt()
    key = KeyDerivation.derive_key_scrypt(password, salt)
    
    # Format: algorithm | salt | hash
    return f"scrypt${base64.b64encode(salt).decode()}${base64.b64encode(key).decode()}"


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    try:
        parts = password_hash.split("$")
        if len(parts) != 3 or parts[0] != "scrypt":
            return False
        
        salt = base64.b64decode(parts[1])
        stored_hash = base64.b64decode(parts[2])
        
        computed_hash = KeyDerivation.derive_key_scrypt(password, salt)
        
        return hmac.compare_digest(computed_hash, stored_hash)
    except Exception:
        return False