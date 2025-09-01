#!/usr/bin/env python3

import os
import sys
import time
import subprocess
import platform
import json
import struct
from pathlib import Path

class ReverseEngineering:
    def __init__(self):
        self.target_files = []
        self.analysis_results = []
        self.strings_found = []
        
    def analyze_binary_file(self, file_path):
        print(f"[+] Analyzing binary file: {file_path}")
        
        if not os.path.exists(file_path):
            print(f"    [-] File not found: {file_path}")
            return
            
        file_info = {
            "path": file_path,
            "size": os.path.getsize(file_path),
            "type": self.detect_file_type(file_path),
            "entropy": self.calculate_entropy(file_path)
        }
        
        self.target_files.append(file_info)
        
        self.extract_strings(file_path)
        self.analyze_file_structure(file_path)
        
    def detect_file_type(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
            if header.startswith(b'MZ'):
                return "PE Executable"
            elif header.startswith(b'\x7fELF'):
                return "ELF Executable"
            elif header.startswith(b'\xfe\xed\xfa'):
                return "Mach-O Executable"
            elif header.startswith(b'PK'):
                return "ZIP Archive"
            else:
                return "Unknown Binary"
        except:
            return "Unknown"
            
    def calculate_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if len(data) == 0:
                return 0.0
                
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1
                
            entropy = 0.0
            for count in byte_counts:
                if count > 0:
                    probability = count / len(data)
                    entropy -= probability * (probability.bit_length() - 1)
                    
            return round(entropy, 2)
        except:
            return 0.0
            
    def extract_strings(self, file_path):
        print("    [+] Extracting strings...")
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        self.strings_found.append({
                            "file": file_path,
                            "string": current_string,
                            "length": len(current_string)
                        })
                    current_string = ""
                    
            if len(current_string) >= 4:
                self.strings_found.append({
                    "file": file_path,
                    "string": current_string,
                    "length": len(current_string)
                })
                
            print(f"        [+] Found {len([s for s in self.strings_found if s['file'] == file_path])} strings")
            
        except Exception as e:
            print(f"        [-] Error extracting strings: {e}")
            
    def analyze_file_structure(self, file_path):
        print("    [+] Analyzing file structure...")
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            analysis = {
                "file": file_path,
                "total_size": len(data),
                "null_bytes": data.count(b'\x00'),
                "readable_chars": sum(1 for b in data if 32 <= b <= 126),
                "control_chars": sum(1 for b in data if b < 32 or b > 126),
                "suspicious_patterns": []
            }
            
            suspicious_patterns = [
                (b'http://', 'HTTP URL'),
                (b'https://', 'HTTPS URL'),
                (b'cmd.exe', 'Command Prompt'),
                (b'powershell', 'PowerShell'),
                (b'regsvr32', 'Registry Server'),
                (b'rundll32', 'Run DLL')
            ]
            
            for pattern, description in suspicious_patterns:
                if pattern in data:
                    analysis["suspicious_patterns"].append({
                        "pattern": pattern.decode('utf-8', errors='ignore'),
                        "description": description,
                        "count": data.count(pattern)
                    })
                    
            self.analysis_results.append(analysis)
            print(f"        [+] Analysis complete")
            
        except Exception as e:
            print(f"        [-] Error analyzing structure: {e}")
            
    def generate_reverse_report(self):
        print("\n===============================================")
        print("    Reverse Engineering Analysis Report")
        print("===============================================")
        
        print(f"Files analyzed: {len(self.target_files)}")
        print(f"Strings extracted: {len(self.strings_found)}")
        print(f"Analysis results: {len(self.analysis_results)}")
        
        if self.target_files:
            print("\nTarget Files:")
            for file_info in self.target_files:
                print(f"File: {os.path.basename(file_info['path'])}")
                print(f"   Type: {file_info['type']}")
                print(f"   Size: {file_info['size']} bytes")
                print(f"   Entropy: {file_info['entropy']}")
                print()
                
        if self.analysis_results:
            print("\nAnalysis Results:")
            for result in self.analysis_results:
                print(f"File: {os.path.basename(result['file'])}")
                print(f"   Total Size: {result['total_size']} bytes")
                print(f"   Null Bytes: {result['null_bytes']}")
                print(f"   Readable Chars: {result['readable_chars']}")
                print(f"   Control Chars: {result['control_chars']}")
                
                if result['suspicious_patterns']:
                    print("   Suspicious Patterns:")
                    for pattern in result['suspicious_patterns']:
                        print(f"     - {pattern['pattern']}: {pattern['description']} ({pattern['count']} occurrences)")
                print()
                
        if self.strings_found:
            print("\nInteresting Strings:")
            interesting_strings = [s for s in self.strings_found if len(s['string']) > 8]
            for i, string_info in enumerate(interesting_strings[:10], 1):
                print(f"{i}. {string_info['string'][:50]}...")
                print(f"   Length: {string_info['length']}")
                print()
                
        self.save_report()
        
    def save_report(self):
        report_file = "reverse_engineering_report.json"
        
        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "author": "@Bengamin_Button",
            "team": "@XillenAdapter",
            "platform": platform.system(),
            "target_files": self.target_files,
            "analysis_results": self.analysis_results,
            "strings_found": self.strings_found,
            "summary": {
                "total_files": len(self.target_files),
                "total_strings": len(self.strings_found),
                "total_analyses": len(self.analysis_results)
            }
        }
        
        try:
            with open(report_file, 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"[+] Report saved to: {report_file}")
        except Exception as e:
            print(f"[-] Error saving report: {e}")
            
    def run_reverse_engineering(self):
        print("===============================================")
        print("    XILLEN Reverse Engineering")
        print("    Обратная инженерия")
        print("===============================================")
        print("Author: @Bengamin_Button")
        print("Team: @XillenAdapter")
        print()
        
        sample_files = ["sample.exe", "test.bin", "unknown.dat"]
        
        for sample_file in sample_files:
            if os.path.exists(sample_file):
                self.analyze_binary_file(sample_file)
                print()
            else:
                print(f"[+] Creating sample file for analysis: {sample_file}")
                with open(sample_file, 'wb') as f:
                    f.write(b'Hello World\x00\x00\x00http://example.com\x00cmd.exe\x00')
                self.analyze_binary_file(sample_file)
                print()
                
        self.generate_reverse_report()

def main():
    re = ReverseEngineering()
    re.run_reverse_engineering()

if __name__ == "__main__":
    main()
