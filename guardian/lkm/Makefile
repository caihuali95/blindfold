obj-m += Guardian.o
Guardian-objs := guardian.o guardian_aarch64.o guardian_debug.o libguardian.o
LINUX ?= "../../build/rpi/build_linux/"

all:
	rustup default nightly
	rustup target add aarch64-unknown-none
	cargo -Z unstable-options -C $(RUSTSRC) build --target-dir $(OUT) --target=aarch64-unknown-none
	cp $(OUT)/aarch64-unknown-none/debug/libguardian.a $(CURDIR)/libguardian.o
	touch $(CURDIR)/.libguardian.o.cmd
	make -j12 -C $(LINUX) M="$(CURDIR)" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- modules

clean:
	make -j12 -C $(LINUX) M="$(CURDIR)" ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- clean