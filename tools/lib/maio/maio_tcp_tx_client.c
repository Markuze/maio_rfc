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

	int idx, len;
	void *cache = init_hp_memory(PAGE_CNT);
	char *buffer = alloc_page(cache);

	printf("init memory and get page %p\n", buffer);
	len = snprintf(buffer, 64, "Hello MAIO!\n");

	idx = create_connected_socket(dip, port);
	printf("Connected maio sock =%d\n", idx);
	init_tcp_ring(idx, cache);

	printf("sending [%s]\n", buffer);
	send_buffer(idx, buffer, len, 0);

	return 0;
}
