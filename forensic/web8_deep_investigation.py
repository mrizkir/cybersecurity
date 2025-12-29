#!/usr/bin/env python3
"""
Round 3 - Deep Investigation: web8 Directory
Focus on /var/www/clients/client3/web8/web/

Author: Mochammad Rizki Romdoni
Date: 2024-12-29
"""

import subprocess
import os
import json
from datetime import datetime

class Web8Investigator:
    def __init__(self):
        self.web8_path = "/var/www/clients/client3/web8/web"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"/tmp/web8_investigation_{self.timestamp}"
        self.findings = []
        
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"[+] Web8 Deep Investigation Started")
        print(f"[+] Target: {self.web8_path}")
        print(f"[+] Output: {self.output_dir}")
        print("="*80)
    
    def run_cmd(self, cmd, desc):
        """Execute command safely"""
        print(f"\n[*] {desc}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def find_watcher_asin(self):
        """Find watcher.php and asin.php mentioned in forensic report"""
        print("\n" + "="*80)
        print("STEP 1: Find watcher.php and asin.php")
        print("="*80)
        
        output = self.run_cmd(
            f"sudo find {self.web8_path} -type f \\( -name 'watcher.php' -o -name 'asin.php' \\) 2>/dev/null",
            "Searching for watcher.php and asin.php"
        )
        
        if output.strip():
            print(f"[!] FOUND: {output}")
            self.findings.append({
                'type': 'suspicious_files',
                'files': output.strip().split('\n')
            })
        else:
            print("[+] Not found in direct search")
        
        with open(f"{self.output_dir}/watcher_asin_search.txt", "w") as f:
            f.write(output)
        
        return output
    
    def list_all_php_files(self):
        """List ALL PHP files in web8"""
        print("\n" + "="*80)
        print("STEP 2: Complete PHP File Inventory")
        print("="*80)
        
        output = self.run_cmd(
            f"sudo find {self.web8_path} -type f -name '*.php' 2>/dev/null | head -100",
            "Listing all PHP files (first 100)"
        )
        
        print(f"[+] Found PHP files")
        
        with open(f"{self.output_dir}/all_php_files.txt", "w") as f:
            f.write(output)
        
        return output
    
    def find_obfuscated_code(self):
        """Find PHP files with obfuscation patterns"""
        print("\n" + "="*80)
        print("STEP 3: Obfuscation Pattern Detection")
        print("="*80)
        
        patterns = [
            ("eval(base64_decode", "Base64 eval"),
            ("eval(gzinflate", "Gzinflate eval"),
            ("eval(str_rot13", "ROT13 eval"),
            ("assert(base64", "Assert base64"),
            ("create_function", "Create function"),
            ("\\$\\$", "Variable variables"),
            ("chr(", "Character encoding")
        ]
        
        all_suspicious = []
        
        for pattern, desc in patterns:
            print(f"\n[*] Searching for: {desc}")
            output = self.run_cmd(
                f"sudo grep -r -l '{pattern}' {self.web8_path} --include='*.php' 2>/dev/null | head -20",
                f"Finding files with {desc}"
            )
            
            if output.strip() and "Binary file" not in output:
                files = output.strip().split('\n')
                print(f"    [!] Found {len(files)} files")
                all_suspicious.extend(files)
                
                self.findings.append({
                    'type': 'obfuscation',
                    'pattern': desc,
                    'files': files
                })
        
        # Remove duplicates
        unique_suspicious = list(set(all_suspicious))
        
        with open(f"{self.output_dir}/obfuscated_files.txt", "w") as f:
            f.write("\n".join(unique_suspicious))
        
        print(f"\n[+] Total unique suspicious files: {len(unique_suspicious)}")
        
        return unique_suspicious
    
    def check_recently_modified(self):
        """Find recently modified files (last 7 days)"""
        print("\n" + "="*80)
        print("STEP 4: Recently Modified Files (Last 7 Days)")
        print("="*80)
        
        for days in [1, 3, 7]:
            output = self.run_cmd(
                f"sudo find {self.web8_path} -type f -name '*.php' -mtime -{days} 2>/dev/null",
                f"Files modified in last {days} days"
            )
            
            if output.strip():
                files = output.strip().split('\n')
                print(f"    [+] Last {days} days: {len(files)} files")
                
                with open(f"{self.output_dir}/modified_last_{days}_days.txt", "w") as f:
                    f.write(output)
    
    def check_suspicious_names(self):
        """Find files with suspicious naming patterns"""
        print("\n" + "="*80)
        print("STEP 5: Suspicious File Names")
        print("="*80)
        
        patterns = [
            ("Hidden files", "-name '.*php'"),
            ("Single char", "-name '?.php'"),
            ("Two char", "-name '??.php'"),
            ("Random 8+ chars", "-regex '.*[a-z0-9]{8,}\\.php$'"),
            ("Uppercase PHP", "-name '*.PHP'"),
            ("Double extension", "-name '*.php.*'"),
        ]
        
        for desc, pattern in patterns:
            output = self.run_cmd(
                f"sudo find {self.web8_path} -type f {pattern} 2>/dev/null | head -20",
                f"Finding: {desc}"
            )
            
            if output.strip():
                print(f"    [!] Found: {desc}")
                print(f"    {output[:200]}")
    
    def check_world_writable(self):
        """Find world-writable PHP files"""
        print("\n" + "="*80)
        print("STEP 6: World-Writable PHP Files")
        print("="*80)
        
        output = self.run_cmd(
            f"sudo find {self.web8_path} -type f -name '*.php' -perm -002 2>/dev/null",
            "Finding world-writable files"
        )
        
        if output.strip():
            print(f"[!] DANGEROUS: Found world-writable files")
            print(output)
            
            with open(f"{self.output_dir}/world_writable.txt", "w") as f:
                f.write(output)
    
    def inspect_top_suspicious(self, suspicious_files):
        """Inspect content of most suspicious files"""
        print("\n" + "="*80)
        print("STEP 7: Content Inspection of Top Suspicious Files")
        print("="*80)
        
        for idx, filepath in enumerate(suspicious_files[:5], 1):
            print(f"\n--- File {idx}: {filepath} ---")
            
            # Get file info
            stat_output = self.run_cmd(
                f"sudo stat {filepath} 2>/dev/null",
                f"Getting file info for {filepath}"
            )
            
            # Get first 30 lines
            content = self.run_cmd(
                f"sudo head -30 {filepath} 2>/dev/null",
                f"Reading first 30 lines"
            )
            
            print(f"Content preview:\n{content[:500]}...")
            
            # Save full content
            full_content = self.run_cmd(
                f"sudo cat {filepath} 2>/dev/null",
                f"Reading full content"
            )
            
            safe_filename = filepath.replace('/', '_')
            with open(f"{self.output_dir}/content_{safe_filename}.txt", "w") as f:
                f.write(f"=== STAT INFO ===\n{stat_output}\n\n")
                f.write(f"=== CONTENT ===\n{full_content}")
    
    def check_upload_directories(self):
        """Check common upload directories for malware"""
        print("\n" + "="*80)
        print("STEP 8: Upload Directory Analysis")
        print("="*80)
        
        upload_dirs = [
            "wp-content/uploads",
            "uploads",
            "tmp",
            "temp",
            "cache",
            "images",
            "media"
        ]
        
        for dir_name in upload_dirs:
            full_path = f"{self.web8_path}/{dir_name}"
            output = self.run_cmd(
                f"sudo find {full_path} -type f -name '*.php' 2>/dev/null | head -20",
                f"Checking {dir_name} for PHP files"
            )
            
            if output.strip():
                print(f"    [!] SUSPICIOUS: PHP files in {dir_name}")
                print(f"    {output}")
                
                self.findings.append({
                    'type': 'php_in_uploads',
                    'location': dir_name,
                    'files': output.strip().split('\n')
                })
    
    def generate_report(self):
        """Generate investigation report"""
        print("\n" + "="*80)
        print("GENERATING REPORT")
        print("="*80)
        
        report_file = f"{self.output_dir}/web8_investigation_report.txt"
        
        with open(report_file, "w") as f:
            f.write("="*80 + "\n")
            f.write("WEB8 DEEP INVESTIGATION REPORT\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Total findings: {len(self.findings)}\n\n")
            
            for idx, finding in enumerate(self.findings, 1):
                f.write(f"\n{idx}. Type: {finding['type']}\n")
                f.write(f"   Details: {json.dumps(finding, indent=4)}\n")
        
        print(f"[+] Report saved: {report_file}")
        print(f"[+] All data in: {self.output_dir}/")
        
        return report_file


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║           WEB8 DEEP INVESTIGATION - ROUND 3                  ║
    ║              Focus: /var/www/clients/client3/web8/web/       ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        print("[!] This script requires sudo privileges")
        exit(1)
    
    investigator = Web8Investigator()
    
    try:
        # Execute investigation steps
        investigator.find_watcher_asin()
        investigator.list_all_php_files()
        suspicious = investigator.find_obfuscated_code()
        investigator.check_recently_modified()
        investigator.check_suspicious_names()
        investigator.check_world_writable()
        investigator.check_upload_directories()
        
        if suspicious:
            investigator.inspect_top_suspicious(suspicious)
        
        report = investigator.generate_report()
        
        print("\n[+] Investigation completed!")
        print(f"[+] Review report: {report}")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()