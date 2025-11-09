"""
Cryptographic utilities for image encryption and decryption using AES-256-CBC.
Handles key derivation, encryption, decryption, and padding operations.
"""

import os
from base64 import b64encode
from typing import Tuple, Union

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

class CryptoError(Exception):
    """Custom exception for cryptographic operations."""
    pass

def derive_key(password: str, salt: bytes = None, iterations: int = 200000) -> Tuple[bytes, bytes]:
    """
    Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256.
    
    Args:
        password: User-provided password string
        salt: Optional salt (16 bytes), generated if not provided
        iterations: Number of PBKDF2 iterations
        
    Returns:
        Tuple of (derived_key, salt)
    """
    if not salt:
        salt = os.urandom(16)
    
    if not isinstance(password, str) or not password:
        raise CryptoError("Invalid password provided")
        
    try:
        key = PBKDF2(
            password.encode(),
            salt,
            dkLen=32,  # 256 bits
            count=iterations,
            hmac_hash_module=SHA256
        )
        return key, salt
    except Exception as e:
        raise CryptoError(f"Key derivation failed: {str(e)}")

def encrypt_image(image_data: bytes, password: str) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt image data using AES-256-CBC with PKCS7 padding.
    
    Args:
        image_data: Raw image bytes to encrypt
        password: User-provided password string
        
    Returns:
        Tuple of (salt, iv, encrypted_data)
    """
    try:
        # Generate salt and derive key
        key, salt = derive_key(password)
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Create cipher object and encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(image_data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        
        return salt, iv, encrypted_data
        
    except Exception as e:
        raise CryptoError(f"Encryption failed: {str(e)}")

def decrypt_image(encrypted_data: bytes, salt: bytes, iv: bytes, password: str) -> bytes:
    """
    Decrypt image data using AES-256-CBC and remove PKCS7 padding.
    
    Args:
        encrypted_data: Encrypted image bytes
        salt: Salt used for key derivation (16 bytes)
        iv: Initialization vector used for encryption (16 bytes)
        password: User-provided password string
        
    Returns:
        Decrypted image bytes
    """
    try:
        # Derive key using provided salt
        key, _ = derive_key(password, salt)
        
        # Create cipher object and decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        
        # Remove padding
        decrypted_data = unpad(decrypted_padded, AES.block_size)
        return decrypted_data
        
    except Exception as e:
        raise CryptoError(f"Decryption failed: {str(e)}")

def combine_encrypted_data(salt: bytes, iv: bytes, encrypted_data: bytes) -> bytes:
    """Combine salt, IV, and encrypted data into a single byte string."""
    return salt + iv + encrypted_data

def split_encrypted_data(combined_data: bytes) -> Tuple[bytes, bytes, bytes]:
    """Split combined encrypted data back into salt, IV, and encrypted data."""
    if len(combined_data) < 32:  # Minimum length check (16 bytes salt + 16 bytes IV)
        raise CryptoError("Invalid encrypted data format")
    
    salt = combined_data[:16]
    iv = combined_data[16:32]
    encrypted_data = combined_data[32:]
    
    return salt, iv, encrypted_data

def create_visualization_image(encrypted_data: bytes, original_size: Tuple[int, int] = None) -> 'Image':
    """
    Create a visual representation of encrypted data as an image.
    
    Args:
        encrypted_data: The encrypted bytes to visualize
        original_size: Optional tuple of (width, height) of original image
        
    Returns:
        PIL Image object representing the encrypted data
    """
    try:
        from PIL import Image
        import numpy as np
        
        # Convert encrypted bytes to numpy array
        data_array = np.frombuffer(encrypted_data, dtype=np.uint8)
        
        if original_size:
            # Try to reshape to original dimensions if possible
            target_size = original_size
            # If data doesn't fit exactly, adjust to nearest fitting rectangle
            total_pixels = len(data_array)
            if total_pixels < original_size[0] * original_size[1]:
                width = int(np.sqrt(total_pixels))
                height = total_pixels // width
                target_size = (width, height)
        else:
            # Find the nearest square or rectangle that can fit the data
            width = int(np.sqrt(len(data_array)))
            height = len(data_array) // width
            target_size = (width, height)
            
        # Reshape the array to 2D
        reshaped_array = data_array[:target_size[0] * target_size[1]].reshape(target_size[::-1])
        
        # Create image from array
        return Image.fromarray(reshaped_array, mode='L')  # 'L' for grayscale
        
    except Exception as e:
        raise CryptoError(f"Failed to create visualization image: {str(e)}")