CC=gcc
CFLAGS=-I.
DEPS=user_maio.h

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)


maio_tcp_tx_client: maio_lib.o maio_tcp_tx_client.o
	$(CC) -o maio_tcp_tx_client maio_lib.o maio_tcp_tx_client.o

clean:
	rm -f *.o
