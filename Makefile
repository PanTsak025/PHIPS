CLANG ?= clang
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)

# The BPF program needs to know the CPU architecture: syscall numbers and register names differ.
ARCH := $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')

.PHONY: all clean vmlinux install selftest

all: probe.bpf.o loader

probe.bpf.o: probe.bpf.c vmlinux.h event.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wno-missing-declarations \
		-c probe.bpf.c -o probe.bpf.o

loader: loader.c event.h
	$(CLANG) -g -O2 -Wall $(LIBBPF_CFLAGS) loader.c -o loader $(LIBBPF_LIBS) -lz

# Regenerate vmlinux.h from the running kernel (needs bpftool). Not required: thanks to CO-RE, a
# vmlinux.h from any recent kernel works on other kernels too.
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Installs the collector as a systemd service (see deploy/phips-collector.service)
install: all
	install -d /opt/phips
	install -m 0755 loader /opt/phips/loader
	install -m 0644 probe.bpf.o /opt/phips/probe.bpf.o
	install -m 0644 docs/COLLECTOR.md /opt/phips/COLLECTOR.md
	install -m 0644 deploy/phips-collector.service /etc/systemd/system/phips-collector.service
	systemctl daemon-reload
	@echo "now: sudo systemctl enable --now phips-collector"

# End-to-end check on this machine (needs root, python3 with networkx, curl)
selftest: all
	tests/selftest.sh

clean:
	rm -f probe.bpf.o loader
