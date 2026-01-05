# Toolchain

CC      := gcc
CLANG   := clang
BPFTOOL := bpftool
INSTALL := install

CFLAGS     := -O2 -g -Wall  
BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu

LDLIBS := -lbpf -lelf
JSLIB  := -ljansson

# Paths

DYNAMIC_DIR := Dynamic_Tracer
POLICY_DIR  := Policy
BUILD_DIR   := build


# targets

.PHONY: all clean dynamic policy install dirs

all: dirs dynamic policy

dirs:
	mkdir -p $(BUILD_DIR)

# Dynamic Tracer

dynamic: \
	$(BUILD_DIR)/dynamic_tracer \
	$(DYNAMIC_DIR)/dynamic_tracer.bpf.o \
	$(DYNAMIC_DIR)/dynamic_tracer.skel.h

$(DYNAMIC_DIR)/dynamic_tracer.bpf.o: \
	$(DYNAMIC_DIR)/dynamic_tracer.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(DYNAMIC_DIR)/dynamic_tracer.skel.h: \
	$(DYNAMIC_DIR)/dynamic_tracer.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/dynamic_tracer: \
	$(DYNAMIC_DIR)/dynamic_tracer.c \
	$(DYNAMIC_DIR)/dynamic_tracer.skel.h
	$(CC) $(CFLAGS) -o $@ $< -lbpf


# Policy and Sandbox

policy: \
	$(BUILD_DIR)/policy-daemon \
	$(BUILD_DIR)/sandbox-run \
	$(POLICY_DIR)/ebpf_policy.bpf.o \
	$(POLICY_DIR)/ebpf_policy.skel.h

$(POLICY_DIR)/ebpf_policy.bpf.o: \
	$(POLICY_DIR)/ebpf_policy.bpf.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(POLICY_DIR)/ebpf_policy.skel.h: \
	$(POLICY_DIR)/ebpf_policy.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD_DIR)/policy-daemon: \
	$(POLICY_DIR)/policy-daemon.c \
	$(POLICY_DIR)/policy_parser.c \
	$(POLICY_DIR)/ebpf_policy.skel.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) $(JSLIB)

$(BUILD_DIR)/sandbox-run: \
	$(POLICY_DIR)/sandbox-run.c \
	$(POLICY_DIR)/policy_parser.c \
	$(POLICY_DIR)/seccomp_launcher.c \
	$(POLICY_DIR)/ebpf_policy.skel.h
	$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS) $(JSLIB)



# Install

install: $(BUILD_DIR)/policy-daemon
	sudo $(INSTALL) -m 0755 $(BUILD_DIR)/policy-daemon /usr/local/bin/policy-daemon
	sudo cp Policy/policy.service /etc/systemd/system/
	sudo systemctl daemon-reexec
	sudo systemctl enable --now policy.service


# Cleanup

clean:
	rm -rf \
		$(BUILD_DIR) \
		$(DYNAMIC_DIR)/*.o \
		$(DYNAMIC_DIR)/*.skel.h \
		$(POLICY_DIR)/*.o \
		$(POLICY_DIR)/*.skel.h
