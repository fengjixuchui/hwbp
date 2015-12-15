include $(PROJ_ROOT)/Makefile.inc

KMOD = hwbp
KMOD_KO = $(KMOD).ko

obj-m = $(KMOD).o

ccflags-y := -I$(src) -D __KERNEL__ $(COMMON_CFLAGS)

$(KMOD)-y := main.o

KBUILD_EXTRA_SYMBOLS = $(PROJ_ROOT)/crt/kernel/Module.symvers

ifndef KERNEL_PATH
KERNEL_PATH=/lib/modules/$(shell uname -r)/build
endif

all:
	$(MAKE) -C $(KERNEL_PATH) M=$(PROJ_ROOT)/core modules
	cp $(KMOD_KO) ../bin/$(KMOD_KO)
clean:
	$(MAKE) -C $(KERNEL_PATH) M=$(PROJ_ROOT)/core clean
	rm -r -f *.o
