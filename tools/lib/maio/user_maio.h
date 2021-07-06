#ifndef   __USER_MAIO__
#define   __USER_MAIO__

#include <stdint.h>

#define MAP_PROC_NAME		"/proc/maio/map"
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

#endif /*__USER_MAIO__*/
