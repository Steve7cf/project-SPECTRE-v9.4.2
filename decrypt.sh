#!/bin/bash
# CERBERUS FILE DECRYPTION TOOL - SPECIFIC FILE FIX
# For files with .cerberus extension like: Screencast From 2025-10-15 08-28-26.mp4.cerberus

KEY="26@may7cf"

echo "Cerberus Specific File Decryptor"
echo "================================"
echo "Using key: $KEY"
echo ""

decrypt_cerberus_file() {
    local encrypted_file="$1"
    
    # Remove .cerberus extension to get original filename
    local original_file="${encrypted_file%.cerberus}"
    
    echo "[+] Decrypting: $encrypted_file"
    echo "[+] Restoring to: $original_file"
    
    # Check if file exists and has reasonable size
    if [ ! -f "$encrypted_file" ]; then
        echo "[-] File not found: $encrypted_file"
        return 1
    fi
    
    filesize=$(stat -c%s "$encrypted_file" 2>/dev/null || stat -f%z "$encrypted_file" 2>/dev/null)
    if [ "$filesize" -lt 100 ]; then
        echo "[-] File too small, might not be encrypted: $encrypted_file"
        return 1
    fi
    
    # Create Python decryption script
    python3 -c "
import sys
import os

key = b'$KEY'
encrypted_file = '$encrypted_file'
original_file = '$original_file'

try:
    # Read encrypted file
    with open(encrypted_file, 'rb') as f:
        encrypted_data = f.read()
    
    # XOR decryption with the same algorithm Cerberus used
    decrypted_data = bytearray()
    for i in range(len(encrypted_data)):
        k1 = key[i % len(key)]
        k2 = key[(i + 7) % len(key)]
        k3 = key[(i + 13) % len(key)]
        decrypted_byte = encrypted_data[i] ^ k1 ^ k2 ^ k3 ^ (i % 256)
        decrypted_data.append(decrypted_byte)
    
    # Write decrypted file
    with open(original_file, 'wb') as f:
        f.write(decrypted_data)
    
    print(f'[SUCCESS] Decrypted: {encrypted_file} -> {original_file}')
    
    # Verify the file is actually decrypted
    if os.path.getsize(original_file) > 0:
        # Remove the encrypted file
        os.remove(encrypted_file)
        print(f'[CLEANUP] Removed encrypted file: {encrypted_file}')
    else:
        print(f'[WARNING] Decrypted file is empty, keeping original')
        
except Exception as e:
    print(f'[ERROR] Failed to decrypt {encrypted_file}: {e}')
"
}

# Specific file decryption
if [ -f "Screencast From 2025-10-15 08-28-26.mp4.cerberus" ]; then
    echo "[*] Found specific file: Screencast From 2025-10-15 08-28-26.mp4.cerberus"
    decrypt_cerberus_file "Screencast From 2025-10-15 08-28-26.mp4.cerberus"
fi

# Bulk decryption for all .cerberus files
echo ""
echo "[*] Scanning for all .cerberus files..."
find /home -name "*.cerberus" -type f 2>/dev/null | while read file; do
    decrypt_cerberus_file "$file"
done

echo ""
echo "[*] Decryption complete!"
echo "[*] Check if your files are restored properly."