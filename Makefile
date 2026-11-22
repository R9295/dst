CC      := gcc
CFLAGS  := -O3 -g -Wall -Wextra -Wno-unused-parameter -std=gnu11 -Iinclude -D_GNU_SOURCE
LDFLAGS := -pthread

BUILD   := build
SRCS    := src/vmm.c src/mmu.c src/x86_patch.c src/elf_loader.c \
           src/determinism.c src/scheduler.c src/vfs.c src/net.c src/iouring.c \
           src/syscall.c src/snapshot.c src/main.c
OBJS    := $(patsubst src/%.c,$(BUILD)/%.o,$(SRCS)) $(BUILD)/guest_stub_embed.o

.PHONY: all clean test tests

all: $(BUILD)/dethv tests

$(BUILD):
	mkdir -p $(BUILD)

# Assemble Ring-0 guest kernel stub -> flat binary -> C array object
$(BUILD)/guest_stub.o: src/guest_stub.S include/guest_shared.h | $(BUILD)
	$(CC) -Iinclude -c src/guest_stub.S -o $(BUILD)/guest_stub.o

$(BUILD)/guest_stub.bin: $(BUILD)/guest_stub.o
	objcopy -O binary -j .text $(BUILD)/guest_stub.o $(BUILD)/guest_stub.bin

$(BUILD)/guest_stub_embed.c: $(BUILD)/guest_stub.bin
	python3 -c 'import sys; d=open("$(BUILD)/guest_stub.bin","rb").read(); \
		print("#include <stdint.h>"); \
		print("const uint32_t guest_stub_bin_len = %d;" % len(d)); \
		print("const uint8_t guest_stub_bin[] = {"); \
		print(",".join("0x%02x" % b for b in d)); \
		print("};")' > $(BUILD)/guest_stub_embed.c

$(BUILD)/guest_stub_embed.o: $(BUILD)/guest_stub_embed.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: src/%.c include/dethv.h include/internal.h include/guest_shared.h include/syscalls.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/dethv: $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Test binaries (both dynamically-linked and statically-linked unmodified Linux ELF binaries!)
tests: $(BUILD)/nondet_torture_dyn $(BUILD)/nondet_torture_static $(BUILD)/fuzz_target_dyn $(BUILD)/fuzz_target_static

$(BUILD)/nondet_torture_dyn: tests/nondet_torture.c | $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -pthread $< -o $@

$(BUILD)/nondet_torture_static: tests/nondet_torture.c | $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -static -pthread $< -o $@

$(BUILD)/fuzz_target_dyn: tests/fuzz_target.c | $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -pthread $< -o $@

$(BUILD)/fuzz_target_static: tests/fuzz_target.c | $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -static -pthread $< -o $@

test: all
	bash tests/run_tests.sh

clean:
	rm -rf $(BUILD)
