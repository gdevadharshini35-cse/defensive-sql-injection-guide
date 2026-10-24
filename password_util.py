"""
password_util.py - Defensive Database Security Password Utilities
Course: Value Added Course (VAC) in Cybersecurity

Demonstrates industry-standard secure password storage using:
 1. PBKDF2 with HMAC-SHA256 (Password-Based Key Derivation Function 2)
 2. Cryptographically secure random salts (via os.urandom)
 3. High iteration count (65,536 iterations) to defeat brute-force and GPU cracking
 4. Constant-time comparison (hmac.compare_digest) to prevent timing side-channel attacks

EDUCATIONAL NOTE:
Plain text passwords must NEVER be stored in any database. Even simple SHA-256
or MD5 hashing without salt is vulnerable to precomputed Rainbow Table attacks.
Salting ensures that identical passwords yield completely distinct hash outputs.
"""

import os
import hashlib
import hmac

ITERATIONS = 65536
HASH_ALGORITHM = "sha256"
SALT_BYTES = 32


def generate_salt() -> str:
    """Generates a cryptographically secure 32-byte (256-bit) random salt."""
    return os.urandom(SALT_BYTES).hex()


def hash_password(password: str, salt_hex: str) -> str:
    """
    Hashes a password with a hex-encoded salt using PBKDF2-HMAC-SHA256.
    
    :param password: Plain-text password string
    :param salt_hex: 64-character hexadecimal salt string
    :return: 64-character hexadecimal derived hash string
    """
    if not password or not salt_hex:
        raise ValueError("Password and salt cannot be empty.")
    
    salt_bytes = bytes.fromhex(salt_hex)
    password_bytes = password.encode("utf-8")
    
    derived_key = hashlib.pbkdf2_hmac(
        HASH_ALGORITHM,
        password_bytes,
        salt_bytes,
        ITERATIONS,
        dklen=32  # 256 bits = 32 bytes
    )
    return derived_key.hex()


def verify_password(entered_password: str, stored_hash_hex: str, stored_salt_hex: str) -> bool:
    """
    Verifies an entered password against a stored PBKDF2 hash and salt.
    Uses constant-time comparison (hmac.compare_digest) to prevent timing side-channel attacks.
    
    :param entered_password: The password supplied by the user during login
    :param stored_hash_hex: The PBKDF2 hash retrieved from the database
    :param stored_salt_hex: The salt retrieved from the database
    :return: True if credentials match, False otherwise
    """
    if not entered_password or not stored_hash_hex or not stored_salt_hex:
        return False
    
    try:
        computed_hash_hex = hash_password(entered_password, stored_salt_hex)
        # Constant-time comparison defends against timing attacks
        return hmac.compare_digest(computed_hash_hex, stored_hash_hex)
    except Exception:
        return False
