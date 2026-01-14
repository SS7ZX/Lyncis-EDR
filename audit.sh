#!/bin/bash

# Project Lyncis: Automated Security Audit
# This script compiles, deploys, and verifies the EDR mitigation.

echo "--- 🛡️ PROJECT LYNCIS: SYSTEM AUDIT START ---"

# 1. Clean and Build
echo "[*] Compiling BPF Sensor and User-space Collector..."
make clean > /dev/null 2>&1
make > /dev/null 2>&1

if [ $? -ne 0 ]; then
    echo "[!] Compilation failed. Check dependencies (libbpf, clang)."
    exit 1
fi

# 2. Compile PoC Exploit
echo "[*] Preparing Exploit Simulation..."
gcc poc/exploit_sim.c -o poc/exploit_sim

# 3. Launch EDR in Background
echo "[*] Deploying Kernel Guard..."
sudo ./lyncis_edr > audit_log.json 2>&1 &
EDR_PID=$!

# Give EDR a second to attach hooks
sleep 2

# 4. Trigger the Exploit
echo "[🔥] Executing Exploit Simulation (RWX Request)..."
./poc/exploit_sim

# 5. Forensic Verification
sleep 3
echo "[🔍] Searching for Forensic Artifacts..."
LATEST_DUMP=$(ls -t evidence_* | head -1)

if [ -z "$LATEST_DUMP" ]; then
    echo "[❌] FAIL: No forensic evidence captured. Mitigation might have missed."
else
    echo "[✅] SUCCESS: Evidence captured at $LATEST_DUMP"
    echo "[*] Running Signature Scanner..."
    python3 forensics/lyncis_scanner.py "$LATEST_DUMP"
fi

# 6. Cleanup
echo "[*] Shutting down EDR and cleaning up..."
sudo kill $EDR_PID > /dev/null 2>&1
echo "--- 🏁 AUDIT COMPLETE ---"
