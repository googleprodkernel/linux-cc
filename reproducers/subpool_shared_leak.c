// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#define HPAGE_SIZE (2 * 1024 * 1024)

int main(int argc, char **argv)
{
	const char *file_path;
	void *addr;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <file_path>\n", argv[0]);
		return 1;
	}
	file_path = argv[1];

	fd = open(file_path, O_CREAT | O_RDWR, 0666);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	addr = mmap(NULL, 2 * HPAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		perror("mmap");
		close(fd);
		return 1;
	}

	/* Allocate 1st page only. 2nd page remains unallocated (but reserved). */
	*(char *)addr = 1;

	munmap(addr, 2 * HPAGE_SIZE);
	close(fd);

	return 0;
}
