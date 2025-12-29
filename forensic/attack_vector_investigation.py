#!/usr/bin/env python3
"""
Round 3 - Attack Vector Investigation
How did the malware get uploaded?

Author: Mochammad Rizki Romdoni
Date: 2024-12-29
"""

import subprocess
import os
from datetime import datetime
import json

class AttackVectorInvestigator:
    def __init__(self):
        self.web8_path = "/var/www/clients/client3/web8/web"
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = f"/tmp/attack_vector_{self.timestamp}"
        self.malware_files = [
            "/var/www/clients/client3/web8/web/watcher.php",
            "/var/www/clients/client3/web8/web/asin.php",
            "/var/www/clients/client3/web8/web/wp-includes/css/dist/customize-widgets/mairpin.php",
            "/var/www/clients/client3/web8/web/wp-includes/css/dist/patterns/languege.php",
            "/var/www/clients/client3/web8/web/wp-content/maintenance/assets/images/inlinee.php",
            "/var/www/clients/client3/web8/web/wp-content/uploads/2022/05/inlinee.php",
            "/var/www/clients/client3/web8/web/wp-includes/Requests/library/query-smallser-adminer.php",
        ]
        
        os.makedirs(self.output_dir, exist_ok=True)
        print("="*80)
        print("ATTACK VECTOR INVESTIGATION")
        print("Question: How did malware get uploaded?")
        print("="*80)
    
    def run_cmd(self, cmd, desc):
        """Execute command"""
        print(f"\n[*] {desc}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def check_file_timestamps(self):
        """Check when malware files were created/modified"""
        print("\n" + "="*80)
        print("STEP 1: Malware File Timestamps")
        print("="*80)
        
        timeline = {}
        
        for filepath in self.malware_files:
            print(f"\n[*] Checking: {filepath}")
            
            stat_output = self.run_cmd(
                f"sudo stat {filepath} 2>/dev/null",
                f"Getting timestamps"
            )
            
            if stat_output and "No such file" not in stat_output:
                print(stat_output)
                timeline[filepath] = stat_output
            else:
                print(f"    [!] File not found or inaccessible")
        
        with open(f"{self.output_dir}/malware_timestamps.txt", "w") as f:
            for filepath, stat_info in timeline.items():
                f.write(f"\n{'='*80}\n{filepath}\n{'='*80}\n")
                f.write(stat_info)
        
        return timeline
    
    def check_access_logs(self):
        """Check access logs for suspicious uploads"""
        print("\n" + "="*80)
        print("STEP 2: Access Log Analysis - Looking for Upload Attempts")
        print("="*80)
        
        log_paths = [
            "/var/www/clients/client3/web8/log/access.log",
            "/var/log/nginx/access.log",
            "/var/log/apache2/access.log",
        ]
        
        suspicious_patterns = [
            "POST.*wp-admin.*upload",
            "POST.*wp-content.*upload",
            "POST.*admin-ajax",
            "POST.*file-upload",
            "POST.*theme-editor",
            "POST.*plugin-editor",
            "POST.*\.php.*eval",
            "POST.*xmlrpc",
        ]
        
        for log_path in log_paths:
            print(f"\n[*] Checking: {log_path}")
            
            for pattern in suspicious_patterns:
                output = self.run_cmd(
                    f"sudo grep -E '{pattern}' {log_path} 2>/dev/null | tail -50",
                    f"Searching for: {pattern}"
                )
                
                if output.strip() and "No such file" not in output:
                    print(f"    [!] Found matches for {pattern}")
                    print(f"    {output[:200]}...")
                    
                    safe_pattern = pattern.replace('/', '_').replace('*', 'all')
                    with open(f"{self.output_dir}/access_log_{safe_pattern}.txt", "w") as f:
                        f.write(output)
    
    def check_wordpress_vulnerabilities(self):
        """Check for known vulnerable WordPress components"""
        print("\n" + "="*80)
        print("STEP 3: WordPress Vulnerability Assessment")
        print("="*80)
        
        # Check WordPress version
        wp_version_output = self.run_cmd(
            f"sudo grep 'wp_version' {self.web8_path}/wp-includes/version.php 2>/dev/null | head -5",
            "Checking WordPress version"
        )
        print(wp_version_output)
        
        # Check installed plugins
        plugins_output = self.run_cmd(
            f"sudo ls -lah {self.web8_path}/wp-content/plugins/ 2>/dev/null",
            "Listing installed plugins"
        )
        print(f"Installed plugins:\n{plugins_output}")
        
        with open(f"{self.output_dir}/wordpress_info.txt", "w") as f:
            f.write("=== WordPress Version ===\n")
            f.write(wp_version_output)
            f.write("\n\n=== Installed Plugins ===\n")
            f.write(plugins_output)
        
        # Check for known vulnerable plugins
        vulnerable_plugins = [
            "file-manager",
            "wp-file-manager",
            "site-editor",
            "wp-theme-editor",
            "advanced-custom-fields",
        ]
        
        print("\n[*] Checking for known vulnerable plugins:")
        for plugin in vulnerable_plugins:
            check = self.run_cmd(
                f"sudo ls -d {self.web8_path}/wp-content/plugins/*{plugin}* 2>/dev/null",
                f"Looking for {plugin}"
            )
            if check.strip():
                print(f"    [!] FOUND: {plugin}")
                print(f"    {check}")
    
    def check_theme_vulnerabilities(self):
        """Check theme files for vulnerabilities"""
        print("\n" + "="*80)
        print("STEP 4: Theme Security Check")
        print("="*80)
        
        # Check active theme
        active_theme = self.run_cmd(
            f"sudo grep -r 'define.*WP_DEFAULT_THEME' {self.web8_path}/wp-config.php 2>/dev/null",
            "Checking active theme"
        )
        
        # List all themes
        themes = self.run_cmd(
            f"sudo ls -lah {self.web8_path}/wp-content/themes/ 2>/dev/null",
            "Listing installed themes"
        )
        print(themes)
        
        # Check for theme-editor.php (common attack vector)
        theme_editor = self.run_cmd(
            f"sudo ls -lah {self.web8_path}/wp-admin/theme-editor.php 2>/dev/null",
            "Checking if theme editor exists"
        )
        
        if theme_editor.strip() and "No such file" not in theme_editor:
            print("[!] VULNERABLE: Theme editor is accessible!")
    
    def check_file_permissions(self):
        """Check if upload directories have insecure permissions"""
        print("\n" + "="*80)
        print("STEP 5: File Permission Analysis")
        print("="*80)
        
        critical_dirs = [
            f"{self.web8_path}/wp-content/uploads/",
            f"{self.web8_path}/wp-content/plugins/",
            f"{self.web8_path}/wp-content/themes/",
            f"{self.web8_path}/wp-includes/",
        ]
        
        for directory in critical_dirs:
            perm_output = self.run_cmd(
                f"sudo stat {directory} 2>/dev/null | grep 'Access: ('",
                f"Checking permissions for {directory}"
            )
            print(f"{directory}: {perm_output}")
            
            # Check for world-writable
            writable = self.run_cmd(
                f"sudo find {directory} -type d -perm -002 2>/dev/null | head -10",
                f"Finding world-writable dirs in {directory}"
            )
            
            if writable.strip():
                print(f"    [!] DANGEROUS: World-writable directories found!")
                print(writable)
    
    def check_xmlrpc(self):
        """Check if XML-RPC is enabled (common attack vector)"""
        print("\n" + "="*80)
        print("STEP 6: XML-RPC Status")
        print("="*80)
        
        xmlrpc_output = self.run_cmd(
            f"sudo ls -lah {self.web8_path}/xmlrpc.php 2>/dev/null",
            "Checking if xmlrpc.php exists"
        )
        
        if xmlrpc_output.strip() and "No such file" not in xmlrpc_output:
            print("[!] XML-RPC is present - common attack vector for brute force")
            
            # Check access logs for XML-RPC abuse
            xmlrpc_attacks = self.run_cmd(
                f"sudo grep 'POST.*xmlrpc' /var/www/clients/client3/web8/log/access.log 2>/dev/null | tail -20",
                "Checking for XML-RPC abuse in logs"
            )
            
            if xmlrpc_attacks.strip():
                print("[!] XML-RPC attacks detected in logs!")
                print(xmlrpc_attacks)
    
    def check_user_accounts(self):
        """Check for suspicious WordPress user accounts"""
        print("\n" + "="*80)
        print("STEP 7: WordPress User Account Analysis")
        print("="*80)
        
        # Try to read wp-config.php for database credentials
        print("[*] Attempting to extract database credentials...")
        
        db_info = self.run_cmd(
            f"sudo grep -E 'DB_NAME|DB_USER|DB_PASSWORD|DB_HOST' {self.web8_path}/wp-config.php 2>/dev/null",
            "Extracting database configuration"
        )
        
        if db_info.strip():
            print("[+] Database configuration found (credentials redacted in output)")
            
            with open(f"{self.output_dir}/db_config.txt", "w") as f:
                f.write(db_info)
            
            print("\n[*] To check WordPress users, run:")
            print(f"    mysql -u<user> -p<pass> <dbname> -e 'SELECT user_login, user_email, user_registered FROM wp_users;'")
    
    def check_recently_accessed_files(self):
        """Check which files were accessed around malware upload time"""
        print("\n" + "="*80)
        print("STEP 8: Recently Accessed Files Analysis")
        print("="*80)
        
        # Find PHP files accessed in last 30 days
        recent_access = self.run_cmd(
            f"sudo find {self.web8_path} -type f -name '*.php' -atime -30 2>/dev/null | head -50",
            "Files accessed in last 30 days"
        )
        
        print(f"Recently accessed files:\n{recent_access[:500]}...")
        
        with open(f"{self.output_dir}/recently_accessed.txt", "w") as f:
            f.write(recent_access)
    
    def generate_attack_vector_report(self):
        """Generate comprehensive attack vector report"""
        print("\n" + "="*80)
        print("GENERATING ATTACK VECTOR REPORT")
        print("="*80)
        
        report_file = f"{self.output_dir}/attack_vector_report.txt"
        
        with open(report_file, "w") as f:
            f.write("="*80 + "\n")
            f.write("ATTACK VECTOR INVESTIGATION REPORT\n")
            f.write(f"Timestamp: {datetime.now()}\n")
            f.write("="*80 + "\n\n")
            
            f.write("POSSIBLE ATTACK VECTORS:\n")
            f.write("-"*80 + "\n")
            f.write("1. WordPress Plugin Vulnerability\n")
            f.write("   - File Manager plugins (wp-file-manager)\n")
            f.write("   - Theme/Plugin editors\n")
            f.write("   - Outdated plugins with known CVEs\n\n")
            
            f.write("2. XML-RPC Brute Force\n")
            f.write("   - XML-RPC endpoint abuse\n")
            f.write("   - Credential stuffing\n\n")
            
            f.write("3. Theme/Plugin Editor Abuse\n")
            f.write("   - Direct file upload via admin panel\n")
            f.write("   - Code injection via editor\n\n")
            
            f.write("4. Insecure File Permissions\n")
            f.write("   - World-writable directories\n")
            f.write("   - Weak upload directory permissions\n\n")
            
            f.write("5. Compromised Admin Credentials\n")
            f.write("   - Weak passwords\n")
            f.write("   - Credential reuse\n\n")
            
            f.write("\n" + "="*80 + "\n")
            f.write("RECOMMENDED INVESTIGATION STEPS:\n")
            f.write("-"*80 + "\n")
            f.write("1. Check access logs around malware upload time\n")
            f.write("2. Review WordPress user accounts for suspicious admins\n")
            f.write("3. Identify vulnerable plugin versions\n")
            f.write("4. Check for unauthorized file modifications\n")
            f.write("5. Review firewall logs for suspicious IPs\n")
        
        print(f"[+] Report saved: {report_file}")
        print(f"[+] All data in: {self.output_dir}/")
        
        return report_file


def main():
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║              ATTACK VECTOR INVESTIGATION                     ║
    ║          How Did Malware Enter the System?                   ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)
    
    if os.geteuid() != 0:
        print("[!] This script requires sudo privileges")
        exit(1)
    
    investigator = AttackVectorInvestigator()
    
    try:
        investigator.check_file_timestamps()
        investigator.check_access_logs()
        investigator.check_wordpress_vulnerabilities()
        investigator.check_theme_vulnerabilities()
        investigator.check_file_permissions()
        investigator.check_xmlrpc()
        investigator.check_user_accounts()
        investigator.check_recently_accessed_files()
        
        report = investigator.generate_attack_vector_report()
        
        print("\n[+] Investigation completed!")
        print(f"[+] Review report: {report}")
        
        print("\n" + "="*80)
        print("NEXT STEPS:")
        print("-"*80)
        print("1. Review malware_timestamps.txt to see when files were uploaded")
        print("2. Review access logs for suspicious POST requests")
        print("3. Check WordPress users for unauthorized admins")
        print("4. Identify the vulnerable component (plugin/theme)")
        print("5. Proceed to Phase 3: Containment & Eradication")
        
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
    except Exception as e:
        print(f"\n[ERROR] {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()