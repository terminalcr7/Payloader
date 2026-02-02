import struct
import random

class PEBuilder:
    def __init__(self):
        pass
    
    def build_exe(self, code: bytes) -> bytes:
        """Build a Windows EXE"""
        # Simple DOS header
        dos_header = (
            b"MZ" +                     # Signature
            b"\x90" * 58 +              # DOS stub
            struct.pack("<I", 0x80)     # PE header offset
        )
        
        # Simple PE header
        pe_header = (
            b"PE\x00\x00" +            # PE signature
            struct.pack("<H", 0x014C) + # Machine (x86)
            struct.pack("<H", 1) +      # Number of sections
            struct.pack("<I", random.randint(0, 0xFFFFFFFF)) +  # Timestamp
            b"\x00" * 16 +              # Rest of header
            b"\x0B\x01" +               # Characteristics
            b"\x0F\x01" +               # Magic (PE32)
            b"\x00" * 20 +              # More header
            struct.pack("<I", 0x1000)   # Entry point
        )
        
        return dos_header + pe_header + code
    
    def build_dll(self, code: bytes) -> bytes:
        """Build a DLL"""
        return self.build_exe(code)
