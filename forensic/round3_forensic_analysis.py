#!/usr/bin/env python3
"""
Round 3 Forensic Analysis Script
AI-Assisted Incident Response - PHP-FPM Attack Investigation
Based on framework from: AI-Assisted Incident Response paper

Author: Mochammad Rizki Romdoni
Date: 2024-12-29
Server: Ubuntu 22.04 + ISPConfig
Attack Type: Suspected PHP-based malware/webshell
"""

import subprocess
import json
import os
import sys
from datetime import datetime
import re

class Round3ForensicAnalyzer:
    def __init__(self):
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"/root/forensic/round3_forensics_{self.timestamp}"
        self.results = {
            "timestamp": self.timestamp,
            "phase": "Phase 1 - Detection & Assessment",
            "findings": {},
            "suspicious_items": []
        }
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        print(f"[+] Forensic analysis started at {datetime.now()}")
        print(f"[+] Output directory: {self.output_dir}")
        print("=" * 80)
    
    def run_command(self, command, description):
        """Execute command and return output"""
        print(f"\n[*] {description}")
        print(f"[CMD] {command}")
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True,
                timeout=30
            )
            output = result.stdout if result.stdout else result.stderr
            print(f"[OK] Command completed")
            return output
        except subprocess.TimeoutExpired:
            print(f"[WARN] Command timeout")
            return "TIMEOUT"
        except Exception as e:
            print(f"[ERROR] {str(e)}")
            return f"ERROR: {str(e)}"
    
    def analyze_php_fpm_processes(self):
        """Analyze suspicious PHP-FPM processes"""
        print("\n" + "="*80)
        print("STEP 1: PHP-FPM Process Analysis")
        print("="*80)
        
        # Get top CPU processes
        output = self.run_command(
            "ps aux --sort=-%cpu | head -20",
            "Getting top CPU-consuming processes"
        )
        
        # Extract PHP-FPM PIDs and pools
        php_processes = []
        for line in output.split('\n'):
            if 'php-fpm: pool' in line:
                parts = line.split()
                php_processes.append({
                    'user': parts[0],
                    'pid': parts[1],
                    'cpu': parts[2],
                    'mem': parts[3],
                    'start': parts[8],
                    'time': parts[9],
                    'pool': parts[-1]
                })
        
        self.results['findings']['php_processes'] = php_processes
        print(f"\n[+] Found {len(php_processes)} suspicious PHP-FPM processes")
        
        for proc in php_processes[:5]:  # Top 5
            print(f"    PID {proc['pid']}: {proc['pool']} - CPU: {proc['cpu']}% - Running since: {proc['start']}")
        
        # Save to file
        with open(f"{self.output_dir}/php_processes.txt", "w") as f:
            f.write(output)
        
        return php_processes
    
    def investigate_php_files(self, top_pids):
        """Investigate what PHP files are being executed"""
        print("\n" + "="*80)
        print("STEP 2: PHP File Investigation")
        print("="*80)
        
        file_analysis = {}
        
        for proc in top_pids[:3]:  # Top 3 most suspicious
            pid = proc['pid']
            pool = proc['pool']
            
            print(f"\n[*] Analyzing PID {pid} ({pool})")
            
            # Get open files for this PID
            output = self.run_command(
                f"sudo lsof -p {pid} 2>/dev/null | grep -E '\\.php|\\.so'",
                f"Checking open files for PID {pid}"
            )
            
            file_analysis[pid] = {
                'pool': pool,
                'open_files': output,
                'network_connections': None
            }
            
            # Check network connections
            net_output = self.run_command(
                f"sudo netstat -tunap 2>/dev/null | grep {pid}",
                f"Checking network connections for PID {pid}"
            )
            file_analysis[pid]['network_connections'] = net_output
            
            if net_output and net_output.strip():
                print(f"    [!] SUSPICIOUS: PID {pid} has active network connections!")
                self.results['suspicious_items'].append({
                    'type': 'network_connection',
                    'pid': pid,
                    'details': net_output
                })
        
        self.results['findings']['file_analysis'] = file_analysis
        
        # Save to file
        with open(f"{self.output_dir}/file_analysis.json", "w") as f:
            json.dump(file_analysis, f, indent=2)
        
        return file_analysis
    
    def check_web_directories(self):
        """Check for recently modified PHP files in web directories"""
        print("\n" + "="*80)
        print("STEP 3: Web Directory Analysis")
        print("="*80)
        
        web_dirs = [
            "/var/www/clients/client*/web23/web/",
            "/var/www/clients/client*/web8/web/",
            "/var/www/clients/client*/web5/web/"
        ]
        
        suspicious_files = []
        
        for web_dir_pattern in web_dirs:
            print(f"\n[*] Scanning {web_dir_pattern}")
            
            # Find recently modified PHP files (last 24 hours)
            output = self.run_command(
                f"sudo find {web_dir_pattern} -type f -name '*.php' -mtime -1 2>/dev/null | head -20",
                f"Finding recently modified PHP files in {web_dir_pattern}"
            )
            
            if output and output.strip() and "No such file" not in output:
                files = output.strip().split('\n')
                print(f"    [+] Found {len(files)} recently modified PHP files")
                suspicious_files.extend(files)
            
            # Find suspicious patterns
            suspicious_patterns_output = self.run_command(
                f"sudo find {web_dir_pattern} -type f -name '*.php' 2>/dev/null | xargs grep -l -E 'eval|base64_decode|exec|shell_exec|system|passthru' 2>/dev/null | head -10",
                f"Searching for suspicious PHP patterns in {web_dir_pattern}"
            )
            
            if suspicious_patterns_output and suspicious_patterns_output.strip():
                print(f"    [!] SUSPICIOUS: Found PHP files with dangerous functions!")
                self.results['suspicious_items'].append({
                    'type': 'suspicious_php_code',
                    'location': web_dir_pattern,
                    'files': suspicious_patterns_output
                })
        
        self.results['findings']['suspicious_files'] = suspicious_files
        
        # Save to file
        with open(f"{self.output_dir}/suspicious_files.txt", "w") as f:
            f.write("\n".join(suspicious_files))
        
        return suspicious_files
    
    def check_logs(self):
        """Check PHP-FPM and access logs"""
        print("\n" + "="*80)
        print("STEP 4: Log Analysis")
        print("="*80)
        
        logs_to_check = [
            "/var/log/php*-fpm.log",
            "/var/log/ispconfig/httpd/*/error.log",
            "/var/www/clients/client*/log/*.log"
        ]
        
        for log_pattern in logs_to_check:
            print(f"\n[*] Checking {log_pattern}")
            
            output = self.run_command(
                f"sudo tail -100 {log_pattern} 2>/dev/null | grep -E 'error|warning|fatal' | tail -20",
                f"Analyzing {log_pattern}"
            )
            
            if output and output.strip():
                print(f"    [+] Found log entries")
                
                # Save to file
                log_file_name = log_pattern.replace("/", "_").replace("*", "all")
                with open(f"{self.output_dir}/log_{log_file_name}.txt", "w") as f:
                    f.write(output)
    
    def check_hidden_processes(self):
        """Check for hidden cryptomining or backdoor processes"""
        print("\n" + "="*80)
        print("STEP 5: Hidden Process Detection")
        print("="*80)
        
        # Check for common malware patterns
        patterns = [
            ("curl|wget", "Download utilities running"),
            ("xmrig|kinsing|miner", "Known cryptominer names"),
            ("/tmp/\\.\\.\\/", "Hidden processes in tmp"),
            ("base64", "Base64 encoding (possible obfuscation)")
        ]
        
        for pattern, description in patterns:
            output = self.run_command(
                f"sudo ps aux | grep -E '{pattern}' | grep -v grep",
                f"Checking for: {description}"
            )
            
            if output and output.strip():
                print(f"    [!] FOUND: {description}")
                self.results['suspicious_items'].append({
                    'type': 'hidden_process',
                    'pattern': pattern,
                    'output': output
                })
    
    def check_network_connections(self):
        """Check all suspicious network connections"""
        print("\n" + "="*80)
        print("STEP 6: Network Connection Analysis")
        print("="*80)
        
        output = self.run_command(
            "sudo netstat -tunap | grep ESTABLISHED | grep -E 'php-fpm|:443|:80'",
            "Checking established connections from PHP-FPM"
        )
        
        self.results['findings']['network_connections'] = output
        
        # Save to file
        with open(f"{self.output_dir}/network_connections.txt", "w") as f:
            f.write(output)
        
        # Parse for suspicious IPs
        if output:
            lines = output.split('\n')
            for line in lines:
                if line.strip():
                    # Extract remote IP addresses
                    match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)', line)
                    if match:
                        remote_ip = match.group(1)
                        remote_port = match.group(2)
                        
                        # Skip local/private IPs
                        if not remote_ip.startswith(('127.', '192.168.', '10.', '172.')):
                            print(f"    [!] External connection: {remote_ip}:{remote_port}")
    
    def generate_report(self):
        """Generate comprehensive forensic report"""
        print("\n" + "="*80)
        print("GENERATING FORENSIC REPORT")
        print("="*80)
        
        report_file = f"{self.output_dir}/forensic_report_{self.timestamp}.txt"
        
        with open(report_file, "w") as f:
            f.write("="*80 + "\n")
            f.write("ROUND 3 FORENSIC ANALYSIS REPORT\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write("="*80 + "\n\n")
            
            f.write("SUMMARY OF FINDINGS\n")
            f.write("-"*80 + "\n")
            f.write(f"Total suspicious items found: {len(self.results['suspicious_items'])}\n\n")
            
            if self.results['suspicious_items']:
                f.write("SUSPICIOUS ITEMS:\n")
                for idx, item in enumerate(self.results['suspicious_items'], 1):
                    f.write(f"\n{idx}. Type: {item['type']}\n")
                    f.write(f"   Details: {str(item)[:200]}...\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("="*80 + "\n")
            f.write(json.dumps(self.results['findings'], indent=2))
        
        # Save JSON version
        json_file = f"{self.output_dir}/forensic_data_{self.timestamp}.json"
        with open(json_file, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n[+] Report saved to: {report_file}")
        print(f"[+] JSON data saved to: {json_file}")
        
        return report_file
    
    def print_summary(self):
        """Print executive summary"""
        print("\n" + "="*80)
        print("EXECUTIVE SUMMARY")
        print("="*80)
        
        print(f"\n[+] Analysis completed at {datetime.now()}")
        print(f"[+] Total suspicious items: {len(self.results['suspicious_items'])}")
        
        if self.results['suspicious_items']:
            print("\n[!] CRITICAL FINDINGS:")
            for item in self.results['suspicious_items'][:5]:
                print(f"    - {item['type']}")
        else:
            print("\n[+] No critical suspicious items detected")
            print("[*] High CPU usage may be due to:")
            print("    - Legitimate high traffic")
            print("    - Database query optimization needed")
            print("    - Application-level issues")
        
        print(f"\n[+] All forensic data saved to: {self.output_dir}/")
        print("\n[*] Next Steps:")
        print("    1. Review the forensic report")
        print("    2. Investigate suspicious files manually")
        print("    3. Check application logs for the affected websites")
        print("    4. Consider isolating affected web pools if malware confirmed")


def main():
    """Main execution function"""
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         ROUND 3 FORENSIC ANALYSIS - PHP-FPM ATTACK           ║
    ║                AI-Assisted Incident Response                  ║
    ║              Mochammad Rizki Romdoni - 2024                  ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[!] WARNING: This script should be run with sudo for full analysis")
        print("[*] Some commands may fail without root privileges")
        response = input("\nContinue anyway? (y/N): ")
        if response.lower() != 'y':
            sys.exit(1)
    
    # Initialize analyzer
    analyzer = Round3ForensicAnalyzer()
    
    try:
        # Execute analysis steps
        print("\n[*] Starting comprehensive forensic analysis...")
        
        # Step 1: Analyze PHP-FPM processes
        php_processes = analyzer.analyze_php_fpm_processes()
        
        # Step 2: Investigate PHP files being executed
        if php_processes:
            analyzer.investigate_php_files(php_processes)
        
        # Step 3: Check web directories for malicious files
        analyzer.check_web_directories()
        
        # Step 4: Analyze logs
        analyzer.check_logs()
        
        # Step 5: Check for hidden processes
        analyzer.check_hidden_processes()
        
        # Step 6: Network connection analysis
        analyzer.check_network_connections()
        
        # Generate report
        report_file = analyzer.generate_report()
        
        # Print summary
        analyzer.print_summary()
        
        print("\n[+] Forensic analysis completed successfully!")
        print(f"[+] Review the full report: {report_file}")
        
    except KeyboardInterrupt:
        print("\n\n[!] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()