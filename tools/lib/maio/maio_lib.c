/**
	MAIO user-space lib
**/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
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

/*
	Allocate HP Memory
		name: file name for hugepagefile
		nr_pages: number of 2MB huge pages
		base_addr : the user address of mapped region start

*/
int init_hp_memory(char *name, void **base_addr, int nr_pages)
{
	int fd, map_proc;

	/* create hp file */
	fd  = open(FILE_NAME, O_CREAT | O_RDWR, 0755);
	if (fd < 0) {
		perror("Open failed");
		return fd;
	}

	/* mmap hp file */
	*base_addr = mmap(ADDR, LENGTH, PROTECTION, FLAGS, fd, 0);
	if (addr == MAP_FAILED) {
		printf("Error Mapping %llu [%llu]\n", LENGTH, NR_PAGES);
		perror("mmap");
		unlink(FILE_NAME);
		return -1;
	}

	/* Create MTT for MAIO */
        if ((map_proc = open(MAP_PROC_NAME, O_RDWR)) < 0) {
                MAIO_LOG(ERR, "Failed to init internals %d\n", __LINE__);
                return -ENODEV;
        }

        printf(">>> base_addr %p len %d [2MB pages]\n", base_addr, NR_PAGES);
        len  = snprintf(write_buffer, 64, "%llx %u\n", (unsigned long long)base_addr, NR_PAGES);
        len = write(map_proc, write_buffer, len);

        printf(">>> Sent %s [2MB = %x]\n", write_buffer, (1<<21));

        close(map_proc);

	return fd;
}

