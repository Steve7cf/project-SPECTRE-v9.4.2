#!/bin/bash
# SPECTRE KILL SWITCH v2 - Fixed Complete Removal Tool
# Save as: spectre_kill.sh then: chmod +x spectre_kill.sh && sudo ./spectre_kill.sh

echo "[SPECTRE KILL SWITCH] Activated - Complete System Cleanup"
echo "========================================================="

# Detect platform
detect_platform() {
    if [ -f /etc/debian_version ]; then
        echo "Debian/Ubuntu detected"
        return 0
    elif [ -f /etc/redhat-release ]; then
        echo "RHEL/CentOS detected" 
        return 1
    elif [[ "$(uname)" == "Darwin" ]]; then
        echo "macOS detected"
        return 2
    else
        echo "Unknown platform - using generic Linux cleanup"
        return 3
    fi
}

# Kill all Spectre processes
kill_processes() {
    echo "[+] Terminating Spectre processes..."
    pkill -f "spectre" 2>/dev/null
    pkill -f "systemd-network" 2>/dev/null
    pkill -f "WindowsDefenderUpdate" 2>/dev/null
    pkill -f "libc.so" 2>/dev/null
    
    # Force kill if needed
    sleep 2
    pkill -9 -f "spectre" 2>/dev/null
    pkill -9 -f "systemd-network" 2>/dev/null
    pkill -9 -f "WindowsDefenderUpdate" 2>/dev/null
    pkill -9 -f "libc.so" 2>/dev/null
    
    echo "[+] Spectre processes terminated"
}

# Remove SSH backdoor
remove_ssh_backdoor() {
    echo "[+] Removing SSH backdoor..."
    if [ -f ~/.ssh/authorized_keys ]; then
        # Use grep -F for fixed string matching to avoid option errors
        grep -F -v "ssh-rsa AAAAB3NzaC1yc2E" ~/.ssh/authorized_keys > ~/.ssh/authorized_keys.tmp 2>/dev/null
        if [ $? -eq 0 ]; then
            mv ~/.ssh/authorized_keys.tmp ~/.ssh/authorized_keys
            chmod 600 ~/.ssh/authorized_keys
            echo "[+] SSH backdoor removed from authorized_keys"
        else
            rm -f ~/.ssh/authorized_keys.tmp
        fi
    fi
}

# Remove LD_PRELOAD backdoor  
remove_ld_preload() {
    echo "[+] Removing LD_PRELOAD backdoor..."
    
    # Remove the file
    rm -f ~/.config/.libc.so 2>/dev/null
    rm -f ~/.libc.so 2>/dev/null
    rm -f /tmp/.libc.so 2>/dev/null
    
    # Remove from shell configs using sed (no grep issues)
    if [ -f ~/.bashrc ]; then
        sed -i.bak '/LD_PRELOAD/d' ~/.bashrc 2>/dev/null
    fi
    if [ -f ~/.profile ]; then
        sed -i.bak '/LD_PRELOAD/d' ~/.profile 2>/dev/null
    fi
    if [ -f ~/.zshrc ]; then
        sed -i.bak '/LD_PRELOAD/d' ~/.zshrc 2>/dev/null
    fi
    
    # Remove backup files
    rm -f ~/.bashrc.bak ~/.profile.bak ~/.zshrc.bak 2>/dev/null
    
    echo "[+] LD_PRELOAD backdoor removed"
}

# Remove cron persistence - FIXED VERSION
remove_cron_persistence() {
    echo "[+] Removing cron persistence..."
    
    # Check if crontab exists and remove spectre entries safely
    if command -v crontab >/dev/null 2>&1; then
        # Get current crontab
        current_cron=$(crontab -l 2>/dev/null)
        
        if [ $? -eq 0 ] && [ -n "$current_cron" ]; then
            # Remove lines containing spectre or the binary patterns
            new_cron=$(echo "$current_cron" | grep -v "spectre" | grep -v "daemon" | grep -v "persist")
            
            # Only update if changes were made
            if [ "$current_cron" != "$new_cron" ]; then
                echo "$new_cron" | crontab -
                echo "[+] User crontab cleaned"
            fi
        fi
    fi
    
    # Remove system cron files
    rm -f /etc/cron.d/system-update 2>/dev/null
    rm -f /etc/cron.d/spectre 2>/dev/null
    rm -f /var/spool/cron/crontabs/root 2>/dev/null
    
    echo "[+] Cron persistence removed"
}

# Remove systemd service
remove_systemd_service() {
    echo "[+] Removing systemd service..."
    
    systemctl stop systemd-network.service 2>/dev/null
    systemctl disable systemd-network.service 2>/dev/null
    rm -f /etc/systemd/system/systemd-network.service 2>/dev/null
    rm -f /usr/lib/systemd/system/systemd-network.service 2>/dev/null
    systemctl daemon-reload 2>/dev/null
    
    echo "[+] Systemd service removed"
}

# Remove binary files
remove_binaries() {
    echo "[+] Removing Spectre binaries..."
    
    # Common installation paths
    rm -f /usr/lib/.systemd-daemon 2>/dev/null
    rm -f /var/lib/.cache-manager 2>/dev/null
    rm -f /tmp/.X11-unix/.Xsession 2>/dev/null
    rm -f ~/.local/share/system-services/spectre 2>/dev/null
    
    # Check common binary names
    find /usr/bin -name "*spectre*" -delete 2>/dev/null
    find /usr/local/bin -name "*spectre*" -delete 2>/dev/null
    find /tmp -name "*spectre*" -delete 2>/dev/null
    find /var/tmp -name "*spectre*" -delete 2>/dev/null
    
    # Remove any file with our signature
    find /home -type f -exec grep -l "CERBERUS_ACTIVE" {} \; -delete 2>/dev/null
    find /root -type f -exec grep -l "CERBERUS_ACTIVE" {} \; -delete 2>/dev/null
    find /opt -type f -exec grep -l "CERBERUS_ACTIVE" {} \; -delete 2>/dev/null
    
    echo "[+] Binary files removed"
}

# Remove Windows artifacts (if on Linux with Wine)
remove_windows_artifacts() {
    echo "[+] Removing Windows artifacts..."
    
    # Wine paths
    if [ -d ~/.wine ]; then
        rm -rf ~/.wine/drive_c/users/*/AppData/Roaming/Microsoft/Windows/System32_Backup/ 2>/dev/null
        rm -rf ~/.wine/drive_c/ProgramData/WindowsNT/Drivers/ 2>/dev/null
        rm -rf ~/.wine/drive_c/Windows/Temp/WindowsUpdate/ 2>/dev/null
        echo "[+] Windows artifacts removed"
    fi
}

# Clear logs and traces
clear_logs() {
    echo "[+] Clearing system logs..."
    
    # Use sed instead of grep to avoid option issues
    if [ -f /var/log/auth.log ]; then
        sed -i.bak '/spectre\|systemd-network/d' /var/log/auth.log 2>/dev/null
        rm -f /var/log/auth.log.bak 2>/dev/null
    fi
    
    if [ -f /var/log/syslog ]; then
        sed -i.bak '/spectre\|systemd-network/d' /var/log/syslog 2>/dev/null
        rm -f /var/log/syslog.bak 2>/dev/null
    fi
    
    # Shell history
    if [ -n "$BASH" ]; then
        history -c 2>/dev/null
    fi
    rm -f ~/.bash_history 2>/dev/null
    rm -f ~/.zsh_history 2>/dev/null
    
    # Temporary files
    rm -f /tmp/.cron 2>/dev/null
    rm -f /tmp/cronjob 2>/dev/null
    rm -f /tmp/spectre_key 2>/dev/null
    
    echo "[+] Logs and traces cleared"
}

# Restore encrypted files (if possible)
restore_encrypted_files() {
    echo "[+] Attempting to restore encrypted files..."
    
    # Use a loop to avoid command line too long errors
    find /home -name "*.encrypted" -type f 2>/dev/null | while read file; do
        mv "$file" "${file%.encrypted}" 2>/dev/null
    done
    
    find /home -name "*.locked" -type f 2>/dev/null | while read file; do
        mv "$file" "${file%.locked}" 2>/dev/null
    done
    
    find /home -name "*.crypted" -type f 2>/dev/null | while read file; do
        mv "$file" "${file%.crypted}" 2>/dev/null
    done
    
    find /home -name "*.secure" -type f 2>/dev/null | while read file; do
        mv "$file" "${file%.secure}" 2>/dev/null
    done
    
    find /home -name "*.rnsmwr" -type f 2>/dev/null | while read file; do
        mv "$file" "${file%.rnsmwr}" 2>/dev/null
    done
    
    echo "[+] File extensions restored (manual decryption may be needed)"
}

# Check for any remaining traces
final_check() {
    echo "[+] Performing final system check..."
    
    # Check for running processes
    if pgrep -f "spectre\|systemd-network\|WindowsDefenderUpdate" > /dev/null 2>&1; then
        echo "[-] WARNING: Some Spectre processes still running!"
        ps aux | grep -v grep | grep -E "spectre|systemd-network|WindowsDefenderUpdate"
    else
        echo "[+] No Spectre processes running"
    fi
    
    # Check for files
    if find /home /root /opt -name "*spectre*" -o -name "*.libc.so" 2>/dev/null | grep -q .; then
        echo "[-] WARNING: Some Spectre files still present"
    else
        echo "[+] No Spectre files found"
    fi
    
    echo "[+] Final check complete"
}

# Main cleanup function
main_cleanup() {
    echo "Starting comprehensive Spectre removal..."
    echo ""
    
    # Detect platform
    detect_platform
    
    # Stop processes first
    kill_processes
    
    # Remove persistence mechanisms
    remove_ssh_backdoor
    remove_ld_preload
    remove_cron_persistence
    remove_systemd_service
    
    # Remove files
    remove_binaries
    remove_windows_artifacts
    
    # Clean up traces
    clear_logs
    
    # Attempt file restoration
    restore_encrypted_files
    
    # Final verification
    final_check
    
    echo ""
    echo "[✓] SPECTRE REMOVAL COMPLETE"
    echo ""
    echo "Recommended next steps:"
    echo "1. Reboot the system"
    echo "2. Change all passwords"
    echo "3. Update your system: sudo apt update && sudo apt upgrade"
    echo "4. Run antivirus scan: sudo apt install clamav && sudo freshclam && sudo clamscan -r /"
    echo "5. Monitor for any suspicious activity"
    echo ""
    echo "Note: Encrypted files may need manual decryption with key: 26@may7cf"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] WARNING: Not running as root. Some cleanup may fail."
    echo "[-] Run with: sudo ./spectre_kill.sh"
    read -p "Continue anyway? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Confirm execution
echo "This will remove all Spectre components from your system."
read -p "Are you sure? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    main_cleanup
else
    echo "Cleanup cancelled."
    exit 0
fi