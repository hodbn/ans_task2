obj-m += nf_task2.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean

