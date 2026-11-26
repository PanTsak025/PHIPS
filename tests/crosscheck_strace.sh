#!/bin/bash
# Compare the collector with strace, an independent tracer (ptrace based), on the same workload.
#   sudo tests/crosscheck_strace.sh
# Prints, per event type, what both saw, what only strace saw (MISSED by the collector) and what
# only the collector saw (EXTRA). Supported operations should match 100%.
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
command -v strace >/dev/null || { echo "install strace: sudo apt install strace"; exit 1; }
W=$(mktemp -d /tmp/phips-crosscheck.XXXXXX)

./loader > "$W/capture.jsonl" 2> "$W/loader.err" &
LOADER=$!
sleep 2
strace -f -qq -yy -s 256 -o "$W/strace.txt" \
  -e trace=open,openat,openat2,creat,read,pread64,readv,preadv,preadv2,write,pwrite64,writev,pwritev,pwritev2,recvfrom,recvmsg,recvmmsg,sendto,sendmsg,sendmmsg,sendfile,splice,copy_file_range,connect,accept,accept4,execve,execveat,clone,clone3,fork,vfork \
  bash tests/workload.sh "$W"
sleep 1
kill -INT $LOADER; wait $LOADER
python3 tests/crosscheck_strace.py "$W/strace.txt" "$W/capture.jsonl"
STATUS=$?
echo "files kept in $W"
exit $STATUS
