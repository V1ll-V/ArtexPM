#!/usr/bin/env bash
set -u

cat << 'EOF' > /tmp/test_ghidra.c
#include <stdio.h>
int check(int x) { return x * 42 + 7; }
int main() { printf("%d\n", check(5)); return 0; }
EOF

gcc -O0 -o /tmp/test_ghidra /tmp/test_ghidra.c
h=$(sha256sum -- /tmp/test_ghidra 2>/dev/null | cut -c1-12)
pdir="/tmp/ghidra_$h"
rm -rf "$pdir"

cleanup() {
    rm -rf /tmp/test_ghidra.c /tmp/test_ghidra /tmp/cold.log /tmp/hot.log "$pdir"
}
trap cleanup EXIT

echo "=== FIRST RUN (Cold: Import + Full Analysis) ==="
t0=$(date +%s%N)
mkdir -p "$pdir"
analyzeHeadless "$pdir" proj -import /tmp/test_ghidra -analysisTimeoutPerFile 180 -scriptPath /opt/ctf/scripts -postScript ExportFunctions.java check 1 >/tmp/cold.log 2>&1
t1=$(date +%s%N)
cold_ms=$(( (t1 - t0) / 1000000 ))
echo "Cold run duration: ${cold_ms} ms"
grep -A 8 "=== check @" /tmp/cold.log || tail -n 15 /tmp/cold.log

echo "=== SECOND RUN (Hot: Cached Project + -noanalysis) ==="
t2=$(date +%s%N)
analyzeHeadless "$pdir" proj -process test_ghidra -noanalysis -scriptPath /opt/ctf/scripts -postScript ExportFunctions.java main 1 >/tmp/hot.log 2>&1
t3=$(date +%s%N)
hot_ms=$(( (t3 - t2) / 1000000 ))
echo "Hot run duration: ${hot_ms} ms"
grep -A 8 "=== main @" /tmp/hot.log || tail -n 15 /tmp/hot.log

speedup=$(awk -v c="$cold_ms" -v h="$hot_ms" 'BEGIN { if (h > 0) printf "%.2f", c / h; else print "N/A" }')
echo "=========================================="
echo "Ghidra Cold Run: ${cold_ms} ms"
echo "Ghidra Hot Run:  ${hot_ms} ms"
echo "Speedup Factor:  ${speedup}x"
echo "=========================================="
