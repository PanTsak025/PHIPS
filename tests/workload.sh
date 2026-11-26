#!/bin/bash
# A varied, realistic workload used by crosscheck_strace.sh. Everything stays inside $1.
W="$1"; cd "$W" || exit 1
mkdir -p www src && printf '#!/bin/sh\ncat /etc/passwd > %s/loot.txt\n' "$W" > www/x.sh
for i in $(seq 1 20); do echo "line $i" > src/f$i.txt; done
python3 -m http.server 18081 --bind 127.0.0.1 --directory www >/dev/null 2>&1 &
SRV=$!; sleep 1
curl -s -o x.sh http://127.0.0.1:18081/x.sh && chmod +x x.sh && ./x.sh
cat /etc/hostname /etc/os-release > info.txt
grep -r "line 1" src > grep.out
sort src/*.txt | uniq -c > sorted.txt
tar cf archive.tar src && tar xf archive.tar -C www
cp /bin/true a.bin && mv a.bin renamed.bin && ./renamed.bin
dd if=/dev/zero of=zero.bin bs=4k count=16 status=none
echo "echo piped > $W/p.txt" | sh
env definitely_not_a_command 2>/dev/null
python3 - <<'PY'
import socket, threading
srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen()
port = srv.getsockname()[1]
def serve():
    c, _ = srv.accept(); c.sendall(c.recv(100).upper()); c.close()
t = threading.Thread(target=serve); t.start()
cli = socket.create_connection(("127.0.0.1", port)); cli.sendall(b"hello"); cli.recv(100); cli.close(); t.join()
socket.socket(socket.AF_INET, socket.SOCK_DGRAM).sendto(b"x", ("127.0.0.53", 53))
readers = [threading.Thread(target=lambda: open("/etc/hostname").read()) for _ in range(4)]
[r.start() for r in readers]; [r.join() for r in readers]
PY
kill $SRV
