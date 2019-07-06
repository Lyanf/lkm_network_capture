obj-m += net.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -Wall client.c -o client

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm client
