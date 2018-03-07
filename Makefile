obj-m := radio.o
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD = $(shell pwd)
all: radio
radio:
	$(MAKE) -C $(KERNEL_DIR) SUBDIRS=$(PWD)
clean:
	rm -rf *.o *.ko *.symvers *.mod.* *.order
static:
	gcc -DDETACH -Wall -s -o x86_64-redhat-linux-cpp prism.c
