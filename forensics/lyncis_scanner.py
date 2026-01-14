import os
import re

# Common Byte Patterns for Linux Shellcode
SIGNATURES = {
    "NOP_SLED": b'\x90\x90\x90\x90',
    "INT_80_SYSCALL": b'\xcd\x80',
    "X64_SYSCALL": b'\x0f\x05',
    "REVERSE_SHELL_STR": b'/bin/sh',
}

def scan_file(filepath):
    print(f"[*] Scanning {filepath} for malicious artifacts...")
    if not os.path.exists(filepath):
        print("[-] File not found.")
        return

    with open(filepath, 'rb') as f:
        data = f.read()
        for name, sig in SIGNATURES.items():
            matches = [m.start() for m in re.finditer(re.escape(sig), data)]
            if matches:
                print(f"[🔥] FOUND {name} at offsets: {['0x%x' % m for m in matches]}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan_file(sys.argv[1])
