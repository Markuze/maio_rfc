#ifndef   __USER_MAIO__
#define   __USER_MAIO__

#include <stdint.h>

#define MAP_PROC_NAME		"/proc/maio/map"
#define STATE_PROC_NAME		"/proc/maio/get_state"
#define TCP_RING_PROC_NAME	"/proc/maio/tcp/ring_setup"
#define TCP_SOCK_PROC_NAME	"/proc/maio/tcp/create"
#define TCP_TX_PROC_NAME	"/proc/maio/tcp/tcp_tx"
#define PAGE_SIZE		0x1000
#define PAGE_SHIFT		12
#define NR_PAGES 		(512ULL)
#define HP_SIZE_LOG		21
#define HP_SIZE 		(1<<HP_SIZE_LOG)	//2MB Files
#define HP_MASK			(HP_SIZE-1)
#define FILE_NAME 		"/mnt/huge/hugepagefile"
#define LENGTH 			(NR_PAGES * HP_SIZE)
#define PROTECTION 		(PROT_READ | PROT_WRITE)


#define STR_IP(a,b,c,d) (a<<24|b<<16|c<<8|d)

struct single_list {
	struct single_list *next;
};

struct page_cache {
	struct single_list *page_list;		//4k Pages
	struct single_list *comp_page_list;	//any other size
	uint32_t chunk_sz;			//the size in pages of chunks in comp_list
	uint32_t chunk_log;			//log of
	int fd;					//fd of the hp file desctiptor
};

struct ring_md {
	int fd;					//fd of the ring file desctiptor
	int state_fd;				//fd for the get_state
	int batch_count;
	uint32_t tx_idx;
	uint32_t ring_sz;
	struct sock_md *sock_md;
};

/****************** Kernel Structs **************************/
#define MAIO_KERNEL_BUFFER      0x1
#define MAIO_BAD_BUFFER         0x2
#define MAIO_SMD_FREE           0x4

struct sock_md {
        uint64_t uaddr;
        uint32_t len; //8 lsb state: 24 size
        uint16_t state;
        uint16_t flags;
};
/************************************************************/

int create_connected_socket(uint32_t ip, uint16_t port);
int init_tcp_ring(int idx, struct page_cache *cache);
struct page_cache *init_hp_memory(int nr_pages);

int send_buffer(int idx, void *buffer, int len, int more);

void *alloc_chunk(struct page_cache *cache);
void *alloc_page(struct page_cache *cache);

int get_state(void *, int idx);
#endif /*__USER_MAIO__*/
