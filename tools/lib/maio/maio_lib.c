/**
	MAIO user-space lib
**/
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "user_maio.h"

/* Only ia64 requires this */
#ifdef __ia64__
#define ADDR (void *)(0x8000000000000000UL)
#define FLAGS (MAP_SHARED | MAP_FIXED)
#else
#define ADDR (void *)(0x0UL)
#define FLAGS (MAP_SHARED)
#endif

#define WRITE_BUFF_LEN 64

/*
	Allocate HP Memory
		name: file name for hugepagefile
		nr_pages: number of 2MB huge pages
		base_addr : the user address of mapped region start

		*cb to create heap -- return heap instead of fd*

*/
static int init_hp_memory(char *name, void **base_addr, int nr_pages)
{
	int fd, map_proc, len;
	char write_buffer[WRITE_BUFF_LEN] = {0};

	/* create hp file */
	fd  = open(FILE_NAME, O_CREAT | O_RDWR, 0755);
	if (fd < 0) {
		perror("Open failed");
		return fd;
	}

	/* mmap hp file */
	*base_addr = mmap(ADDR, LENGTH, PROTECTION, FLAGS, fd, 0);
	if (base_addr == MAP_FAILED) {
		printf("Error Mapping %llu [%llu]\n", LENGTH, NR_PAGES);
		perror("mmap");
		unlink(FILE_NAME);
		return -1;
	}

	/* Create MTT for MAIO */
        if ((map_proc = open(MAP_PROC_NAME, O_RDWR)) < 0) {
                printf("Failed to init internals %d\n", __LINE__);
                return -ENODEV;
        }

        printf(">>> base_addr %p len %lld [2MB pages]\n", *base_addr, NR_PAGES);
        len  = snprintf(write_buffer, 64, "%llx %llu\n", (unsigned long long)base_addr, NR_PAGES);
        len = write(map_proc, write_buffer, len);

        printf(">>> Sent %s [2MB = %x]\n", write_buffer, (1<<21));

        close(map_proc);

	return fd;
}

static inline void add_2MB_HP(struct page_cache *cache, void *addr)
{
	static int	quiet;
	int i;
	size_t chunk_log_step	= PAGE_SHIFT + cache->chunk_log;
	size_t nr_chunks	= (1 << (HP_SIZE_LOG - chunk_log_step));

	if (((uint64_t)addr) & HP_MASK) {
		printf("(%s)Error bad address given %p\n", __FUNCTION__, addr);
		return;
	}

	if (!quiet) {
		quiet = 1;
		printf("nr_chunks = %ld log_step %ld chunk_size %dkb", nr_chunks, chunk_log_step, (1 << chunk_log_step) >> 10);
	}

	//head page is not used for I/O. It holds the external page state
	// next 15 go into a page pool
	for (i = 1; i < cache->chunk_sz; i++) {
		struct single_list *list = addr + (i << PAGE_SHIFT);

		list->next = cache->page_list;
		cache->page_list = list;
	}

	for (i = i; i < nr_chunks; i++) {
		struct single_list *list = addr + (i << chunk_log_step);

		list->next = cache->comp_page_list;
		cache->comp_page_list = list;
	}
}

void *alloc_page(struct page_cache *cache)
{
	void *tmp, *buffer;

	if (!cache->page_list)
		return NULL;

	tmp = cache->page_list->next;
	buffer = cache->page_list;
	cache->page_list = tmp;

	return buffer;
}

void *alloc_chunk(struct page_cache *cache)
{
	void *tmp, *buffer;

	if (!cache->comp_page_list)
		return NULL;

	tmp = cache->comp_page_list->next;
	buffer = cache->comp_page_list;
	cache->comp_page_list = tmp;

	return buffer;
}

struct page_cache *heap_from_hp_memory(void *base, int nr_pages)
{
	struct page_cache cache  = {0};

	cache.chunk_sz 		= 4;
	cache.chunk_log 	= 2;

	while (nr_pages--) {
		add_2MB_HP(&cache, base);
	}
}

int init_tcp_ring(int idx, struct page_cache *cache)
{
	int ring_fd, len;
	char write_buffer[WRITE_BUFF_LEN] = {0};
	void *ring = alloc_chunk(cache);

	if ((ring_fd = open(TCP_RING_PROC_NAME, O_RDWR)) < 0) {
		printf("Failed to init internals %d\n", __LINE__);
		return -ENODEV;
        }

	len  = snprintf(write_buffer, WRITE_BUFF_LEN, "%llx %u %d\n", (unsigned long long)ring,
						(cache->chunk_sz << PAGE_SHIFT),
						idx);

	len = write(ring_fd, write_buffer, len);
	close(ring_fd);

	if (len != len)
		printf("ERROR [%d] writing to %s\n", len, TCP_RING_PROC_NAME);
	return 0;
}

int create_connected_socket(struct page_cache *cache, uint32_t ip, uint16_t port)
{
	int sock_fd, len, idx;
	char write_buffer[WRITE_BUFF_LEN] = {0};
	void *ring = alloc_chunk(cache);

	if ((sock_fd = open(TCP_SOCK_PROC_NAME, O_RDWR)) < 0) {
		printf("Failed to init internals %d\n", __LINE__);
		return -ENODEV;
        }

	len  = snprintf(write_buffer, WRITE_BUFF_LEN, "%d %d\n", ip, port);

	idx = write(sock_fd, write_buffer, len);
	close(sock_fd);

	if (idx < 0)
		printf("ERROR [%d] writing to %s\n", len, TCP_RING_PROC_NAME);
	return idx;

}

