/****
An example of creating a TCP socket and sending Zero-Copy I/O
***/

#include "user_maio.h"

#define PAGE_CNT	512
int main(void)
{
	uint32_t dip = STR_IP(10,5,3,4);
	uint32_t port = 5559;

	void *cache = init_hp_memory(PAGE_CNT);
	int idx = create_connected_socket(dip, port);

	init_tcp_ring(idx, cache);

	return 0;
}
