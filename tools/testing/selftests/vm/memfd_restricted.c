// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright Intel Corporation, 2023
 *
 * Author: Chao Peng <chao.p.peng@linux.intel.com>
 */

#define _GNU_SOURCE
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>


#include "../kselftest.h"

#define fail(fmt, ...) ksft_test_result_fail(fmt, ##__VA_ARGS__)
#define pass(fmt, ...) ksft_test_result_pass(fmt, ##__VA_ARGS__)
#define skip(fmt, ...) ksft_test_result_skip(fmt, ##__VA_ARGS__)

#ifdef __NR_memfd_restricted

static unsigned long page_size;

static int memfd_restricted(unsigned int flags)
{
	return syscall(__NR_memfd_restricted, flags);
}

static void test_file_size(int fd)
{
	struct stat sb;

	if (!ftruncate(fd, page_size + 1)) {
		fail("ftruncate to non page-aligned sizes should fail\n");
		return;
	}

	if (ftruncate(fd, page_size)) {
		fail("ftruncate failed\n");
		return;
	}

	if (fstat(fd, &sb)) {
		fail("fstat failed\n");
		return;
	}

	if (sb.st_size != page_size) {
		fail("unexpected file size after ftruncate\n");
		return;
	}

	if (!ftruncate(fd, page_size * 2)) {
		fail("size of file cannot be changed once set\n");
		return;
	}

	pass("ftruncate/fstat works as expected\n");
}

static void test_file_read_write(int fd)
{
	char buf[64];

	if ((read(fd, buf, sizeof(buf)) >= 0) ||
	    (write(fd, buf, sizeof(buf)) >= 0) ||
	    (pread(fd, buf, sizeof(buf), 0) >= 0) ||
	    (pwrite(fd, buf, sizeof(buf), 0) >= 0))
		fail("unexpected file IO\n");
	else
		pass("file IO is blocked as expected\n");
}

static void test_mmap(int fd)
{
	char *mem;

	mem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem != MAP_FAILED)
		fail("unexpected mmap\n");
	else
		pass("mmap is blocked as expected\n");
}

static void test_fallocate(int fd)
{
	unsigned long total_size = page_size * 4;

	if (fallocate(fd, 0, 0, total_size)) {
		fail("fallocate failed\n");
		return;
	}

	if (!fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
		       page_size - 1, page_size)) {
		fail("unexpected offset accepted by fallocate(PUNCH_HOLE)\n");
		return;
	}

	if (!fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
		       page_size, page_size - 1)) {
		fail("unexpected len accepted by fallocate(PUNCH_HOLE)\n");
		return;
	}

	if (fallocate(fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
		      page_size, page_size)) {
		fail("fallocate(PUNCH_HOLE) failed\n");
		return;
	}

	pass("fallocate works as expected\n");
}

static void prepare(void)
{
	page_size = sysconf(_SC_PAGE_SIZE);
	if (!page_size)
		ksft_exit_fail_msg("Failed to get page size %s\n",
				   strerror(errno));
}

#define NUM_TESTS 4

int main(int argc, char *argv[])
{
	int fd;

	prepare();

	ksft_print_header();
	ksft_set_plan(NUM_TESTS);

	fd = memfd_restricted(0);
	if (fd < 0) {
		if (errno == ENOSYS)
			ksft_exit_skip("memfd_restricted is not supported\n");
		else
			ksft_exit_fail_msg("memfd_restricted failed: %s\n",
					   strerror(errno));
	}

	test_file_size(fd);
	test_file_read_write(fd);
	test_mmap(fd);
	test_fallocate(fd);

	close(fd);

	ksft_finished();
}

#else /* __NR_memfd_restricted */

int main(int argc, char *argv[])
{
	printf("skip: skipping memfd_restricted test (missing __NR_memfd_restricted)\n");
	return KSFT_SKIP;
}

#endif /* __NR_memfd_restricted */
