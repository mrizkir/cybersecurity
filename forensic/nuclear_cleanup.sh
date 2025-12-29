#!/bin/bash
# ROUND 3 - NUCLEAR CLEANUP
# Remove ALL remaining malware files
# Date: 2024-12-29

echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║     ROUND 3 - NUCLEAR MALWARE CLEANUP (50+ FILES)            ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo ""

WEB_ROOT="/var/www/clients/client3/web8/web"
BACKUP_DIR="/root/forensic/nuclear_cleanup_backup_$(date +%s)"

cd "$WEB_ROOT" || exit

# Create backup directory
mkdir -p "$BACKUP_DIR"
echo "[+] Backup directory: $BACKUP_DIR"
echo ""

# Counter
DELETED=0
BACKED_UP=0

echo "════════════════════════════════════════════════════════════════"
echo "PHASE 1: BACKUP & DELETE MODIFIED CORE FILES"
echo "════════════════════════════════════════════════════════════════"

# Modified core files (need replacement)
MODIFIED_FILES=(
    "wp-blog-header.php"
    "wp-login.php"
    "wp-settings.php"
)

for file in "${MODIFIED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "[*] Backing up: $file"
        cp "$file" "$BACKUP_DIR/" 2>/dev/null
        ((BACKED_UP++))
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "PHASE 2: DELETE MALICIOUS FILES THAT SHOULD NOT EXIST"
echo "════════════════════════════════════════════════════════════════"

# All malicious files
MALICIOUS_FILES=(
    # Webshells and backdoors
    "wp-includes/customize/class-wp-widget-customize-control.php"
    "wp-includes/js/mediaelement/renderers/fivesix.php"
    "wp-includes/js/tinymce/plugins/link/detail/index.php"
    "wp-includes/js/imgareaselect/doky.php"
    "wp-includes/SimplePie/Parse/superlite3.php"
    "wp-includes/SimplePie/Content/Type/storage/index.php"
    "wp-includes/ID3/asasx.php"
    "wp-includes/blocks/separator/feed/index.php"
    
    # .htaccess files (suspicious in these locations)
    "wp-includes/js/tinymce/plugins/link/detail/.htaccess"
    "wp-includes/js/tinymce/plugins/link/detail/HOST_DATA/kucrutcgiapi/.htaccess"
    "wp-includes/SimplePie/Content/Type/storage/.htaccess"
    "wp-includes/blocks/separator/feed/.htaccess"
    
    # Backdoor scripts
    "wp-includes/js/tinymce/plugins/link/detail/HOST_DATA/kucrutcgiapi/py.kucrut"
    "wp-includes/js/tinymce/plugins/link/detail/HOST_DATA/kucrutcgiapi/perl.kucrut"
    "wp-includes/js/tinymce/plugins/link/detail/HOST_DATA/kucrutcgiapi/bash.kucrut"
    
    # Error logs (often used to hide malware)
    "wp-includes/customize/error_log"
    "wp-includes/widgets/error_log"
    "wp-includes/block-supports/error_log"
    "wp-includes/sitemaps/providers/error_log"
    "wp-includes/SimplePie/error_log"
    "wp-includes/SimplePie/Cache/error_log"
    "wp-includes/blocks/error_log"
    "wp-includes/theme-compat/error_log"
    "wp-includes/sodium_compat/lib/error_log"
    "wp-includes/sodium_compat/namespaced/error_log"
    "wp-includes/sodium_compat/namespaced/Core/ChaCha20/error_log"
    "wp-includes/sodium_compat/namespaced/Core/Curve25519/Ge/error_log"
    "wp-includes/sodium_compat/namespaced/Core/Curve25519/error_log"
    "wp-includes/sodium_compat/namespaced/Core/error_log"
    "wp-includes/sodium_compat/namespaced/Core/Poly1305/error_log"
    "wp-includes/sodium_compat/src/Core32/ChaCha20/error_log"
    "wp-includes/sodium_compat/src/Core32/Curve25519/error_log"
    "wp-includes/sodium_compat/src/Core32/error_log"
    "wp-includes/sodium_compat/src/Core32/Poly1305/error_log"
    "wp-includes/sodium_compat/src/error_log"
    "wp-includes/sodium_compat/src/Core/ChaCha20/error_log"
    "wp-includes/sodium_compat/src/Core/Curve25519/error_log"
    "wp-includes/sodium_compat/src/Core/error_log"
    "wp-includes/sodium_compat/src/Core/Poly1305/error_log"
    "wp-includes/IXR/error_log"
    "wp-includes/Requests/error_log"
    "wp-includes/block-patterns/error_log"
    "wp-includes/rest-api/fields/error_log"
    "wp-includes/rest-api/endpoints/error_log"
    "wp-includes/rest-api/search/error_log"
    "wp-includes/rest-api/error_log"
    "wp-includes/error_log"
    
    # Other suspicious files
    "wp-admin/js/widgets/.snapshot.json"
)

for file in "${MALICIOUS_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "[!] Deleting: $file"
        # Backup first
        mkdir -p "$BACKUP_DIR/$(dirname "$file")"
        cp "$file" "$BACKUP_DIR/$file" 2>/dev/null
        ((BACKED_UP++))
        
        # Delete
        rm -f "$file" 2>/dev/null && ((DELETED++))
    elif [ -d "$file" ]; then
        echo "[!] Deleting directory: $file"
        cp -r "$file" "$BACKUP_DIR/$file" 2>/dev/null
        rm -rf "$file" 2>/dev/null && ((DELETED++))
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "PHASE 3: REPLACE MODIFIED CORE FILES WITH CLEAN VERSIONS"
echo "════════════════════════════════════════════════════════════════"

# Download clean WordPress if not already done
if [ ! -d "/root/forensic/wordpress" ]; then
    echo "[*] Downloading WordPress 6.4.7..."
    cd /tmp
    wget -q https://wordpress.org/wordpress-6.4.7.tar.gz
    tar -xzf wordpress-6.4.7.tar.gz
    cd "$WEB_ROOT"
fi

echo "[*] Replacing wp-blog-header.php..."
cp /root/forensic/wordpress/wp-blog-header.php "$WEB_ROOT/" 2>/dev/null

echo "[*] Replacing wp-login.php..."
cp /root/forensic/wordpress/wp-login.php "$WEB_ROOT/" 2>/dev/null

echo "[*] Replacing wp-settings.php..."
cp /root/forensic/wordpress/wp-settings.php "$WEB_ROOT/" 2>/dev/null

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "PHASE 4: FIX OWNERSHIP & PERMISSIONS"
echo "════════════════════════════════════════════════════════════════"

echo "[*] Fixing ownership..."
chown -R web8:client3 "$WEB_ROOT"

echo "[*] Fixing permissions..."
find "$WEB_ROOT" -type d -exec chmod 755 {} \;
find "$WEB_ROOT" -type f -exec chmod 644 {} \;

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "PHASE 5: REMOVE SUSPICIOUS DIRECTORIES"
echo "════════════════════════════════════════════════════════════════"

# Remove entire suspicious directories
SUSPICIOUS_DIRS=(
    "wp-includes/js/tinymce/plugins/link/detail/HOST_DATA"
)

for dir in "${SUSPICIOUS_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        echo "[!] Removing directory: $dir"
        rm -rf "$dir" 2>/dev/null && ((DELETED++))
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "PHASE 6: VERIFY CHECKSUMS AGAIN"
echo "════════════════════════════════════════════════════════════════"

cd "$WEB_ROOT"
sudo -u web8 wp core verify-checksums --allow-root 2>&1 | tee "$BACKUP_DIR/final_checksum.log"

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "CLEANUP SUMMARY"
echo "════════════════════════════════════════════════════════════════"
echo "Files backed up: $BACKED_UP"
echo "Files deleted: $DELETED"
echo "Backup location: $BACKUP_DIR"
echo ""
echo "✓ Nuclear cleanup completed!"
echo ""
echo "NEXT STEPS:"
echo "1. Test website functionality"
echo "2. Check wp core verify-checksums output above"
echo "3. If issues remain, consider full WordPress reinstall"
echo "4. Monitor for 48 hours"