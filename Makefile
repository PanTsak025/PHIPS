CLANG ?= clang
LIBBPF_CFLAGS := $(shell pkg-config --cflags libbpf)
LIBBPF_LIBS := $(shell pkg-config --libs libbpf)
 
.PHONY: all clean
 
all: probe.bpf.o loader

probe.bpf.o: probe.bpf.c vmlinux.h event.h
	$(CLANG) -g -O2 -target bpf -c probe.bpf.c -o probe.bpf.o
 
loader: loader.c event.h
	$(CLANG) -g -O2 $(LIBBPF_CFLAGS) loader.c -o loader $(LIBBPF_LIBS)
 
clean:
	rm -f probe.bpf.o loader
