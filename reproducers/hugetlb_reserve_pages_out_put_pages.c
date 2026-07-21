// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>

int main(int argc, char **argv)
{
	const char *file_path;
	size_t size;
	int fd;
	void *addr;

	if (argc < 3) {
		fprintf(stderr, "Usage: %s <hugetlbfs_file> <size_in_bytes>\n",
			argv[0]);
		return 1;
	}

	file_path = argv[1];
	size = strtoull(argv[2], NULL, 0);

	fd = open(file_path, O_CREAT | O_RDWR, 0666);
	if (fd < 0)
		err(1, "open");

	printf("Attempting to mmap %zu bytes shared on %s...\n", size,
	       file_path);
	addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		if (errno == ENOMEM) {
			printf("mmap failed with ENOMEM as expected.\n");
			close(fd);
			return 0;
		}
		perror("mmap failed with unexpected error");
		close(fd);
		return 1;
	}

	printf("ERROR: mmap SUCCEEDED unexpectedly at %p\n", addr);
	munmap(addr, size);
	close(fd);
	return 1;
}
