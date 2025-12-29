cd /var/www/clients/client3/web8/web

# ============================================
# STEP 1: BACKUP ALL INFECTED FILES
# ============================================
echo "[1/8] Backing up infected files..."
sudo mkdir -p /root/forensic/infected_backup_$(date +%s)
sudo cp wp-includes/customize/class-wp-widget-customize-control.php /root/forensic/infected_backup_$(date +%s)/
sudo cp wp-includes/template-loader.php /root/forensic/infected_backup_$(date +%s)/
sudo cp wp-includes/class-wp.php /root/forensic/infected_backup_$(date +%s)/
sudo cp wp-includes/functions.php /root/forensic/infected_backup_$(date +%s)/ 2>/dev/null

# ============================================
# STEP 2: DOWNLOAD CLEAN WORDPRESS 6.4.7
# ============================================
echo "[2/8] Downloading clean WordPress 6.4.7..."
cd /tmp
wget -q https://wordpress.org/wordpress-6.4.7.tar.gz
tar -xzf wordpress-6.4.7.tar.gz

# ============================================
# STEP 3: REPLACE INFECTED FILES
# ============================================
echo "[3/8] Replacing infected core files..."
sudo cp /root/forensic/wordpress/wp-includes/customize/class-wp-widget-customize-control.php \
  /var/www/clients/client3/web8/web/wp-includes/customize/

sudo cp /root/forensic/wordpress/wp-includes/template-loader.php \
  /var/www/clients/client3/web8/web/wp-includes/

sudo cp /root/forensic/wordpress/wp-includes/class-wp.php \
  /var/www/clients/client3/web8/web/wp-includes/

sudo cp /root/forensic/wordpress/wp-includes/functions.php \
  /var/www/clients/client3/web8/web/wp-includes/

# ============================================
# STEP 4: FIX OWNERSHIP
# ============================================
echo "[4/8] Fixing file ownership..."
cd /var/www/clients/client3/web8/web
sudo chown -R web8:client3 wp-includes/

# ============================================
# STEP 5: REMOVE WP-FILE-MANAGER
# ============================================
echo "[5/8] Removing wp-file-manager plugin..."
sudo -u web8 wp plugin uninstall wp-file-manager --allow-root --deactivate 2>/dev/null

# ============================================
# STEP 6: CHECK FOR MALICIOUS ADMIN ACCOUNT
# ============================================
echo "[6/8] Checking for backdoor admin accounts..."
sudo -u web8 wp user list --allow-root --format=table

# Look for suspicious usernames created by malware
# The malware creates user with obfuscated name

# ============================================
# STEP 7: VERIFY CORE INTEGRITY
# ============================================
echo "[7/8] Verifying WordPress core integrity..."
sudo -u web8 wp core verify-checksums --allow-root

# ============================================
# STEP 8: FINAL VALIDATION
# ============================================
echo "[8/8] Final validation..."
echo "Testing website..."
curl -I http://your-domain.com | head -3

echo ""
echo "==================================="
echo "CLEANUP COMPLETED!"
echo "==================================="
echo ""
echo "Infected files backed up to: /root/forensic/infected_backup_*/"
echo ""
echo "NEXT ACTIONS REQUIRED:"
echo "1. Check for malicious WordPress users"
echo "2. Change all admin passwords"
echo "3. Change database password"
echo "4. Monitor for 48 hours"