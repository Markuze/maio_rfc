/****
An example of creating a TCP socket and sending Zero-Copy I/O
***/

#include <stdio.h>
#include "user_maio.h"

#include <unistd.h>

#define PAGE_CNT	512

void *chunk[1024];

int main(void)
{
	uint32_t dip = STR_IP(10,5,3,4);
	uint32_t port = 5559;

	int idx, len = 0, i, slen = 0;

	/* Init Mem*/
	void *cache = init_hp_memory(PAGE_CNT);
	printf("init memory and get page %p\n", cache);

	/* create + connect */
	idx = create_connected_socket(dip, port);
	printf("Connected maio sock =%d\n", idx);

	/* init ring */
	init_tcp_ring(idx, cache);

	/* prep mem for I/O */

	chunk[0] = alloc_chunk(cache);

	slen = (4 << 12);
	printf("send loop [%d]\n", slen);
	while (1) {
		send_buffer(idx, chunk[0], slen, 1);
	};

	return 0;
}
