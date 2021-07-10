/****
An example of creating a TCP socket and sending Zero-Copy I/O
***/

#include <stdio.h>
#include "user_maio.h"

#define PAGE_CNT	512
int main(void)
{
	uint32_t dip = STR_IP(10,5,3,4);
	uint32_t port = 5559;

	int idx, len = 0, i, slen = 0;

	/* Init Mem*/
	void *cache = init_hp_memory(PAGE_CNT);

	/* Alloc page*/
	char *buffer = alloc_page(cache);

	printf("init memory and get page %p\n", buffer);

	/* create + connect */
	idx = create_connected_socket(dip, port);
	printf("Connected maio sock =%d\n", idx);

	/* init ring */
	init_tcp_ring(idx, cache);

	len = slen = snprintf(buffer, 64, "Hello Hello MAIO!!");
	printf("sending [%s]\n", buffer);

	/* send buffer */
	send_buffer(idx, buffer, len, 0);

	printf("send loop\n");
	for (i = 0; i < 8; i++) {
		len = snprintf(&buffer[len], 64, "Hello Hello MAIO!!");
		send_buffer(idx, &buffer[len], slen, 0);
	}
	return 0;
}
