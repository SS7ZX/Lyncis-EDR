# Lyncis Elite Makefile
TARGET := lyncis_edr
BPF_SRC := kernel/lyncis.bpf.c
BPF_OBJ := kernel/lyncis.bpf.o
USER_SRC := src/lyncis_edr.c
SKEL_H := src/lyncis.skel.h

all: $(TARGET)

$(BPF_OBJ): $(BPF_SRC)
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c $< -o $@

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(TARGET): $(USER_SRC) $(SKEL_H)
	gcc -O2 -Wall -Isrc/ -Ikernel/ $< -lbpf -lelf -o $@

clean:
	rm -f $(BPF_OBJ) $(SKEL_H) $(TARGET) evidence_*
