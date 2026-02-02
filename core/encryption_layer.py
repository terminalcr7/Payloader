import random
import hashlib
import os
from typing import Tuple

class EncryptionLayer:
    def __init__(self):
        pass
    
    def multi_layer_encrypt(self, data: bytes, layers: int = 3) -> Tuple[bytes, list]:
        """Encrypt data with multiple layers"""
        keys = []
        encrypted = data
        
        for i in range(layers):
            method = random.choice([self._xor_encrypt, self._rc4_encrypt])
            encrypted, key = method(encrypted)
            keys.append(key)
        
        return encrypted, keys
    
    def _xor_encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        """XOR encryption"""
        key_len = random.randint(4, 32)
        key = os.urandom(key_len)
        
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % key_len])
        
        return bytes(result), key
    
    def _rc4_encrypt(self, data: bytes) -> Tuple[bytes, bytes]:
        """RC4 encryption"""
        key = os.urandom(16)
        
        # Simple RC4 implementation
        S = list(range(256))
        j = 0
        
        # Key scheduling
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # Generate keystream and encrypt
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        
        return bytes(result), key
    
    def _custom_cipher(self, data: bytes) -> Tuple[bytes, bytes]:
        """Custom rolling cipher"""
        seed = random.getrandbits(32)
        key = seed.to_bytes(4, 'little')
        
        result = bytearray()
        rolling_key = int.from_bytes(key, 'little')
        
        for byte in data:
            key_byte = rolling_key & 0xFF
            result.append(byte ^ key_byte)
            rolling_key = ((rolling_key << 1) | (rolling_key >> 31)) & 0xFFFFFFFF
            rolling_key ^= byte
        
        return bytes(result), key
