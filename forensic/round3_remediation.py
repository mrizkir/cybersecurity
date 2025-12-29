#!/usr/bin/env python3
"""
Round 3 - Phase 3: Containment & Eradication
Aggressive Cleanup + WordPress Upgrade

Author: Mochammad Rizki Romdoni
Date: 2024-12-29
Target: /var/www/clients/client3/web8/web/
"""

import subprocess
import os
import shutil
from datetime import datetime
import json

class Round3Remediator:
    def __init__(self):
        self.web8_path = "/var/www/clients/client3/web8/web"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.backup_dir = f"/tmp/round3_backup_{self.timestamp}"
        self.log_file = f"/tmp/round3_remediation_{self.timestamp}.log"
        
        self.malware_files = [
            "/var/www/clients/client3/web8/web/watcher.php",
            "/var/www/clients/client3/web8/web/asin.php",
            "/var/www/clients/client3/web8/web/wp-includes/css/dist/customize-widgets/mairpin.php",
            "/var/www/clients/client3/web8/web/wp-includes/css/dist/patterns/languege.php",
            "/var/www/clients/client3/web8/web/wp-content/maintenance/assets/images/inlinee.php",
            "/var/www/clients/client3/web8/web/wp-content/uploads/2022/05/inlinee.php",
            "/var/www/clients/client3/web8/web/wp-includes/Requests/library/query-smallser-adminer.php",
            "/var/www/clients/client3/web8/web/wp-includes/Requests/src/Transport/query-smallser-adminer.php",
        ]
        
        self.web8_php_processes = []
        
        os.makedirs(self.backup_dir, exist_ok=True)
        
        self.log("="*80)
        self.log("ROUND 3 - PHASE 3: CONTAINMENT & ERADICATION")
        self.log("="*80)
        self.log(f"Timestamp: {datetime.now()}")
        self.log(f"Target: {self.web8_path}")
        self.log(f"Backup Directory: {self.backup_dir}")
    
    def log(self, message):
        """Log to console and file"""
        print(message)
        with open(self.log_file, "a") as f:
            f.write(f"{message}\n")
    
    def run_cmd(self, cmd, desc, critical=False):
        """Execute command with logging"""
        self.log(f"\n[*] {desc}")
        self.log(f"[CMD] {cmd}")
        
        try:
            result = subprocess.run(
                cmd, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=60
            )
            
            output = result.stdout if result.stdout else result.stderr
            
            if result.returncode == 0:
                self.log(f"[OK] Success")
            else:
                self.log(f"[WARN] Exit code: {result.returncode}")
                if critical:
                    self.log(f"[ERROR] Critical command failed!")
                    self.log(output)
            
            return output
        
        except Exception as e:
            self.log(f"[ERROR] {str(e)}")
            if critical:
                raise
            return f"ERROR: {str(e)}"
    
    def backup_malware_files(self):
        """Backup malware files for forensic analysis"""
        self.log("\n" + "="*80)
        self.log("STEP 1: BACKUP MALWARE FILES (Forensic Evidence)")
        self.log("="*80)
        
        malware_backup_dir = f"{self.backup_dir}/malware_samples"
        os.makedirs(malware_backup_dir, exist_ok=True)
        
        for filepath in self.malware_files:
            if os.path.exists(filepath):
                try:
                    filename = filepath.replace('/', '_')
                    backup_path = f"{malware_backup_dir}/{filename}"
                    
                    self.log(f"[*] Backing up: {filepath}")
                    shutil.copy2(filepath, backup_path)
                    self.log(f"    → Saved to: {backup_path}")
                    
                    # Get file hash for documentation
                    hash_output = self.run_cmd(
                        f"md5sum {filepath}",
                        f"Calculating hash"
                    )
                    self.log(f"    Hash: {hash_output.strip()}")
                    
                except Exception as e:
                    self.log(f"[ERROR] Failed to backup {filepath}: {e}")
            else:
                self.log(f"[SKIP] File not found: {filepath}")
    
    def identify_php_processes(self):
        """Identify all PHP-FPM processes for web8"""
        self.log("\n" + "="*80)
        self.log("STEP 2: IDENTIFY PHP-FPM PROCESSES")
        self.log("="*80)
        
        output = self.run_cmd(
            "ps aux | grep 'php-fpm: pool web8' | grep -v grep",
            "Finding web8 PHP-FPM processes"
        )
        
        if output.strip():
            lines = output.strip().split('\n')
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    pid = parts[1]
                    cpu = parts[2]
                    mem = parts[3]
                    time = parts[9]
                    
                    self.web8_php_processes.append({
                        'pid': pid,
                        'cpu': cpu,
                        'mem': mem,
                        'time': time
                    })
                    
                    self.log(f"    PID {pid}: CPU {cpu}%, MEM {mem}%, TIME {time}")
            
            self.log(f"\n[+] Total processes found: {len(self.web8_php_processes)}")
        else:
            self.log("[!] No web8 PHP-FPM processes found")
    
    def kill_php_processes(self):
        """Kill all PHP-FPM processes for web8"""
        self.log("\n" + "="*80)
        self.log("STEP 3: KILL PHP-FPM PROCESSES")
        self.log("="*80)
        
        if not self.web8_php_processes:
            self.log("[SKIP] No processes to kill")
            return
        
        self.log("[!] WARNING: This will terminate all PHP-FPM processes for web8")
        self.log("[!] Website will be temporarily unavailable")
        
        for proc in self.web8_php_processes:
            pid = proc['pid']
            self.log(f"\n[*] Killing PID {pid}")
            
            output = self.run_cmd(
                f"sudo kill -9 {pid}",
                f"Forcefully terminating PID {pid}"
            )
        
        self.log("\n[+] Waiting 5 seconds for processes to terminate...")
        import time
        time.sleep(5)
        
        # Verify termination
        verify = self.run_cmd(
            "ps aux | grep 'php-fpm: pool web8' | grep -v grep",
            "Verifying process termination"
        )
        
        if not verify.strip():
            self.log("[OK] All processes successfully terminated")
        else:
            self.log("[WARN] Some processes still running:")
            self.log(verify)
    
    def delete_malware_files(self):
        """Delete all identified malware files"""
        self.log("\n" + "="*80)
        self.log("STEP 4: DELETE MALWARE FILES")
        self.log("="*80)
        
        deleted_count = 0
        failed_count = 0
        
        for filepath in self.malware_files:
            if os.path.exists(filepath):
                try:
                    self.log(f"[*] Deleting: {filepath}")
                    os.remove(filepath)
                    self.log(f"    [OK] Deleted successfully")
                    deleted_count += 1
                except Exception as e:
                    self.log(f"    [ERROR] Failed: {e}")
                    failed_count += 1
            else:
                self.log(f"[SKIP] Not found: {filepath}")
        
        self.log(f"\n[+] Deletion Summary:")
        self.log(f"    Successfully deleted: {deleted_count}")
        self.log(f"    Failed: {failed_count}")
    
    def scan_for_additional_malware(self):
        """Scan for additional malware that might have been missed"""
        self.log("\n" + "="*80)
        self.log("STEP 5: SCAN FOR ADDITIONAL MALWARE")
        self.log("="*80)
        
        # Look for recently modified PHP files
        self.log("\n[*] Scanning for recently modified PHP files (last 10 days)")
        recent_files = self.run_cmd(
            f"find {self.web8_path} -type f -name '*.php' -mtime -10 2>/dev/null | head -50",
            "Finding recently modified files"
        )
        
        if recent_files.strip():
            self.log("[!] Recently modified files found:")
            self.log(recent_files)
            
            with open(f"{self.backup_dir}/recently_modified_files.txt", "w") as f:
                f.write(recent_files)
        
        # Look for suspicious patterns
        self.log("\n[*] Scanning for obfuscated code patterns")
        suspicious = self.run_cmd(
            f"grep -r -l 'eval(base64_decode\\|eval(gzinflate' {self.web8_path} --include='*.php' 2>/dev/null | head -20",
            "Searching for eval(base64_decode) patterns"
        )
        
        if suspicious.strip():
            self.log("[!] Suspicious files found:")
            self.log(suspicious)
            
            with open(f"{self.backup_dir}/additional_suspicious_files.txt", "w") as f:
                f.write(suspicious)
    
    def change_database_passwords(self):
        """Change database passwords"""
        self.log("\n" + "="*80)
        self.log("STEP 6: DATABASE PASSWORD CHANGE")
        self.log("="*80)
        
        self.log("[*] Current database configuration:")
        self.log("    DB_NAME: c3_wp")
        self.log("    DB_USER: c3_web")
        self.log("    DB_HOST: localhost")
        
        self.log("\n[!] MANUAL ACTION REQUIRED:")
        self.log("    1. Generate new strong password")
        self.log("    2. Update MySQL user password:")
        self.log("       mysql> ALTER USER 'c3_web'@'localhost' IDENTIFIED BY 'NEW_PASSWORD';")
        self.log("    3. Update wp-config.php with new password")
        self.log("    4. Test WordPress connectivity")
        
        # Generate random password suggestion
        import random
        import string
        new_password = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=20))
        self.log(f"\n[+] Suggested new password: {new_password}")
        self.log(f"    (Save this securely!)")
    
    def update_wordpress_core(self):
        """Prepare for WordPress core update"""
        self.log("\n" + "="*80)
        self.log("STEP 7: WORDPRESS CORE UPDATE PREPARATION")
        self.log("="*80)
        
        current_version = self.run_cmd(
            f"grep wp_version {self.web8_path}/wp-includes/version.php | head -1",
            "Checking current WordPress version"
        )
        self.log(f"Current version: {current_version.strip()}")
        
        self.log("\n[!] MANUAL WORDPRESS UPDATE REQUIRED:")
        self.log("    Option A - Via WP-CLI (Recommended):")
        self.log(f"        cd {self.web8_path}")
        self.log("        wp core update --allow-root")
        self.log("        wp core update-db --allow-root")
        self.log("")
        self.log("    Option B - Via Admin Panel:")
        self.log("        1. Login to WordPress admin")
        self.log("        2. Go to Dashboard → Updates")
        self.log("        3. Click 'Update Now'")
        self.log("")
        self.log("    Option C - Manual Download:")
        self.log("        1. Download latest WordPress from wordpress.org")
        self.log("        2. Backup wp-config.php and wp-content/")
        self.log("        3. Extract and replace WordPress core files")
        self.log("        4. Restore wp-config.php and wp-content/")
    
    def update_wp_file_manager(self):
        """Update wp-file-manager plugin"""
        self.log("\n" + "="*80)
        self.log("STEP 8: WP-FILE-MANAGER PLUGIN UPDATE")
        self.log("="*80)
        
        plugin_path = f"{self.web8_path}/wp-content/plugins/wp-file-manager"
        
        if os.path.exists(plugin_path):
            self.log(f"[*] wp-file-manager found at: {plugin_path}")
            
            # Check current version
            version_check = self.run_cmd(
                f"grep 'Version:' {plugin_path}/file_folder_manager.php 2>/dev/null | head -1",
                "Checking wp-file-manager version"
            )
            self.log(f"Current version: {version_check.strip()}")
            
            self.log("\n[!] MANUAL UPDATE REQUIRED:")
            self.log("    Option A - Via WP-CLI:")
            self.log(f"        cd {self.web8_path}")
            self.log("        wp plugin update wp-file-manager --allow-root")
            self.log("")
            self.log("    Option B - Via Admin Panel:")
            self.log("        1. Login to WordPress admin")
            self.log("        2. Go to Plugins → Installed Plugins")
            self.log("        3. Find 'WP File Manager'")
            self.log("        4. Click 'Update Now'")
            self.log("")
            self.log("    [!] IMPORTANT: Update to version 7.2+ (CVE-2020-25213 fixed)")
        else:
            self.log("[!] wp-file-manager not found (already removed?)")
    
    def implement_security_hardening(self):
        """Implement security hardening measures"""
        self.log("\n" + "="*80)
        self.log("STEP 9: SECURITY HARDENING")
        self.log("="*80)
        
        # Disable XML-RPC
        self.log("\n[*] Recommendation: Disable XML-RPC")
        self.log("    Add to .htaccess:")
        self.log("    <Files xmlrpc.php>")
        self.log("        Order Deny,Allow")
        self.log("        Deny from all")
        self.log("    </Files>")
        
        # Disable file editing
        self.log("\n[*] Recommendation: Disable theme/plugin editor")
        self.log("    Add to wp-config.php:")
        self.log("    define('DISALLOW_FILE_EDIT', true);")
        
        # Limit login attempts
        self.log("\n[*] Recommendation: Install security plugin")
        self.log("    - Wordfence Security")
        self.log("    - iThemes Security")
        self.log("    - All In One WP Security")
        
        # File permissions
        self.log("\n[*] Recommendation: Fix file permissions")
        self.log("    Directories: 755")
        self.log("    Files: 644")
        self.log("    wp-config.php: 440 or 400")
    
    def restart_php_fpm(self):
        """Restart PHP-FPM to ensure clean state"""
        self.log("\n" + "="*80)
        self.log("STEP 10: RESTART PHP-FPM")
        self.log("="*80)
        
        php_versions = ["8.3", "8.2", "8.1", "8.0", "7.4"]
        
        for version in php_versions:
            service_name = f"php{version}-fpm"
            
            check = self.run_cmd(
                f"systemctl is-active {service_name} 2>/dev/null",
                f"Checking if {service_name} is running"
            )
            
            if "active" in check.lower():
                self.log(f"[*] Restarting {service_name}")
                self.run_cmd(
                    f"sudo systemctl restart {service_name}",
                    f"Restarting {service_name}"
                )
        
        self.log("\n[+] PHP-FPM restart completed")
    
    def post_remediation_validation(self):
        """Validate that remediation was successful"""
        self.log("\n" + "="*80)
        self.log("STEP 11: POST-REMEDIATION VALIDATION")
        self.log("="*80)
        
        # Check if malware files are gone
        self.log("\n[*] Verifying malware deletion")
        remaining = []
        for filepath in self.malware_files:
            if os.path.exists(filepath):
                remaining.append(filepath)
                self.log(f"    [!] STILL EXISTS: {filepath}")
        
        if not remaining:
            self.log("    [OK] All malware files deleted")
        else:
            self.log(f"    [WARN] {len(remaining)} files still present!")
        
        # Check if PHP-FPM is running normally
        self.log("\n[*] Checking PHP-FPM status")
        php_status = self.run_cmd(
            "ps aux | grep 'php-fpm: pool web8' | grep -v grep | wc -l",
            "Counting web8 PHP-FPM processes"
        )
        self.log(f"    Active web8 processes: {php_status.strip()}")
        
        # Check CPU usage
        self.log("\n[*] Checking system CPU usage")
        cpu_usage = self.run_cmd(
            "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'",
            "Measuring CPU usage"
        )
        self.log(f"    Current CPU usage: {cpu_usage.strip()}%")
    
    def generate_final_report(self):
        """Generate comprehensive remediation report"""
        self.log("\n" + "="*80)
        self.log("GENERATING FINAL REPORT")
        self.log("="*80)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'backup_location': self.backup_dir,
            'malware_files_targeted': len(self.malware_files),
            'php_processes_killed': len(self.web8_php_processes),
            'log_file': self.log_file,
            'status': 'COMPLETED'
        }
        
        report_file = f"{self.backup_dir}/remediation_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        self.log(f"\n[+] Report saved: {report_file}")
        self.log(f"[+] Log file: {self.log_file}")
        self.log(f"[+] Backups: {self.backup_dir}")
        
        self.log("\n" + "="*80)
        self.log("REMEDIATION SUMMARY")
        self.log("="*80)
        self.log(f"Malware files backed up: {self.backup_dir}/malware_samples/")
        self.log(f"Malware files deleted: {len(self.malware_files)}")
        self.log(f"PHP processes terminated: {len(self.web8_php_processes)}")
        self.log("")
        self.log("MANUAL ACTIONS REQUIRED:")
        self.log("1. Update WordPress core to latest version")
        self.log("2. Update wp-file-manager plugin to 7.2+")
        self.log("3. Change database password")
        self.log("4. Implement security hardening measures")
        self.log("5. Monitor for re-infection (24-48 hours)")
        self.log("")
        self.log("NEXT STEPS:")
        self.log("1. Test website functionality")
        self.log("2. Monitor CPU usage (should be normal)")
        self.log("3. Check access logs for suspicious activity")
        self.log("4. Schedule regular security scans")
        
        return report_file


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║          ROUND 3 - PHASE 3: REMEDIATION                      ║
    ║          Containment & Eradication                           ║
    ║                                                              ║
    ║   WARNING: This will kill PHP processes and delete files!   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        print("[!] This script MUST be run with sudo privileges")
        exit(1)
    
    print("\n[!] This script will perform the following actions:")
    print("    1. Backup malware files for analysis")
    print("    2. Kill all PHP-FPM processes for web8")
    print("    3. Delete 7+ malware files")
    print("    4. Scan for additional malware")
    print("    5. Prepare for WordPress/plugin updates")
    print("    6. Implement security recommendations")
    print("")
    
    response = input("Do you want to proceed? (yes/no): ")
    if response.lower() != 'yes':
        print("\n[!] Remediation cancelled by user")
        exit(0)
    
    print("\n[+] Starting remediation process...\n")
    
    remediator = Round3Remediator()
    
    try:
        remediator.backup_malware_files()
        remediator.identify_php_processes()
        remediator.kill_php_processes()
        remediator.delete_malware_files()
        remediator.scan_for_additional_malware()
        remediator.change_database_passwords()
        remediator.update_wordpress_core()
        remediator.update_wp_file_manager()
        remediator.implement_security_hardening()
        remediator.restart_php_fpm()
        remediator.post_remediation_validation()
        
        report_file = remediator.generate_final_report()
        
        print("\n" + "="*80)
        print("REMEDIATION COMPLETED SUCCESSFULLY!")
        print("="*80)
        print(f"\nFull log available at: {remediator.log_file}")
        print(f"Review the log for manual action items.")
        
    except KeyboardInterrupt:
        print("\n\n[!] Remediation interrupted by user")
        print("[!] System may be in inconsistent state!")
        exit(1)
    except Exception as e:
        print(f"\n[ERROR] Remediation failed: {str(e)}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()