import random
import base64
import hashlib
from typing import Dict, List, Tuple
import string

class StringObfuscator:
    def __init__(self):
        self.obfuscation_methods = [
            self._base64_encode,
            self._xor_encode,
            self._aes_encrypt,
            self._rot_encode,
            self._custom_cipher,
            self._split_string,
            self._unicode_escape,
        ]
    
    def obfuscate_string(self, s: str, method: str = "random") -> Tuple[str, str]:
        """Obfuscate a string and return deobfuscation code"""
        if method == "random":
            method_func = random.choice(self.obfuscation_methods)
        else:
            method_map = {m.__name__: m for m in self.obfuscation_methods}
            method_func = method_map.get(method, self._xor_encode)
        
        obfuscated, deobfuscate_code = method_func(s)
        return obfuscated, deobfuscate_code
    
    def _base64_encode(self, s: str) -> Tuple[str, str]:
        """Base64 encoding"""
        encoded = base64.b64encode(s.encode()).decode()
        deobfuscate = f"base64.b64decode('{encoded}').decode()"
        return encoded, deobfuscate
    
    def _xor_encode(self, s: str) -> Tuple[str, str]:
        """XOR encoding with random key"""
        key = random.randint(1, 255)
        encoded_bytes = bytes([ord(c) ^ key for c in s])
        encoded = base64.b64encode(encoded_bytes).decode()
        deobfuscate = f"bytes([b ^ {key} for b in base64.b64decode('{encoded}')]).decode()"
        return encoded, deobfuscate
    
    def _rot_encode(self, s: str, rot: int = 13) -> Tuple[str, str]:
        """ROT13 or custom rotation"""
        if rot == "random":
            rot = random.randint(1, 25)
        
        encoded = ""
        for char in s:
            if 'a' <= char <= 'z':
                encoded += chr((ord(char) - ord('a') + rot) % 26 + ord('a'))
            elif 'A' <= char <= 'Z':
                encoded += chr((ord(char) - ord('A') + rot) % 26 + ord('A'))
            else:
                encoded += char
        
        deobfuscate = f"''.join(chr((ord(c) - ord('a') - {rot}) % 26 + ord('a')) if 'a' <= c <= 'z' else chr((ord(c) - ord('A') - {rot}) % 26 + ord('A')) if 'A' <= c <= 'Z' else c for c in '{encoded}')"
        return encoded, deobfuscate
    
    def _split_string(self, s: str) -> Tuple[str, str]:
        """Split string into parts and concatenate"""
        # Split into random parts
        parts = []
        remaining = s
        while len(remaining) > 0:
            part_size = random.randint(1, max(1, len(remaining) // 3))
            parts.append(remaining[:part_size])
            remaining = remaining[part_size:]
        
        # Encode each part
        encoded_parts = []
        for part in parts:
            method = random.choice([self._base64_encode, self._xor_encode])
            encoded, _ = method(part)
            encoded_parts.append(encoded)
        
        # Create deobfuscation code
        deobfuscate_parts = []
        for i, (part, encoded) in enumerate(zip(parts, encoded_parts)):
            if part == encoded:  # Was base64 encoded
                deobfuscate_parts.append(f"base64.b64decode('{encoded}').decode()")
            else:  # Was XOR encoded
                # We'd need to track the key - simplified here
                deobfuscate_parts.append(f"part_{i}")
        
        deobfuscate = " + ".join(deobfuscate_parts)
        return str(encoded_parts), deobfuscate
    
    def obfuscate_imports(self, imports: List[str]) -> Dict[str, str]:
        """Obfuscate import statements"""
        obfuscated = {}
        
        for imp in imports:
            if imp.startswith("from "):
                # Handle 'from module import something'
                parts = imp.split(" import ")
                module = parts[0].replace("from ", "").strip()
                functions = parts[1].strip()
                
                # Obfuscate module name
                obf_module, deobf_module = self.obfuscate_string(module)
                
                # Obfuscate function names
                func_list = [f.strip() for f in functions.split(",")]
                obf_funcs = []
                deobf_funcs = []
                
                for func in func_list:
                    obf_func, deobf_func = self.obfuscate_string(func)
                    obf_funcs.append(obf_func)
                    deobf_funcs.append(deobf_func)
                
                # Create obfuscated import
                obfuscated[imp] = {
                    "module": obf_module,
                    "functions": obf_funcs,
                    "deobfuscate": f"# Original: {imp}",
                }
            elif imp.startswith("import "):
                # Handle 'import module' or 'import module as alias'
                module = imp.replace("import ", "").strip()
                obf_module, deobf_module = self.obfuscate_string(module)
                
                obfuscated[imp] = {
                    "module": obf_module,
                    "deobfuscate": f"# Original: {imp}",
                }
        
        return obfuscated

class ImportResolver:
    """Resolve imports at runtime to avoid IAT detection"""
    
    def __init__(self):
        self.api_hashes = {}
    
    def generate_resolver(self, dll_name: str, function_name: str) -> str:
        """Generate API hashing resolver code"""
        # Create hash of function name
        hash_val = self._hash_string(function_name)
        self.api_hashes[function_name] = hash_val
        
        resolver_code = f"""
// Resolve {function_name} from {dll_name}
FARPROC resolve_{function_name}() {{
    HMODULE hModule = GetModuleHandleA("{dll_name}");
    if(!hModule) hModule = LoadLibraryA("{dll_name}");
    
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)
        ((BYTE*)hModule + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    
    DWORD* functions = (DWORD*)((BYTE*)hModule + exports->AddressOfFunctions);
    DWORD* names = (DWORD*)((BYTE*)hModule + exports->AddressOfNames);
    WORD* ordinals = (WORD*)((BYTE*)hModule + exports->AddressOfNameOrdinals);
    
    for(DWORD i = 0; i < exports->NumberOfNames; i++) {{
        char* name = (char*)((BYTE*)hModule + names[i]);
        if(hash_string(name) == 0x{hash_val:08X}) {{
            return (FARPROC)((BYTE*)hModule + functions[ordinals[i]]);
        }}
    }}
    return NULL;
}}

// Hash function
DWORD hash_string(char* str) {{
    DWORD hash = 0;
    while(*str) {{
        hash = ((hash << 5) + hash) + *str;
        str++;
    }}
    return hash;
}}
"""
        return resolver_code
    
    def _hash_string(self, s: str) -> int:
        """Simple hash function"""
        hash_val = 0
        for char in s:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
        return hash_val & 0xFFFFFFFF
