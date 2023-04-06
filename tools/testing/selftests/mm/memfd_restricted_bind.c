// SPDX-License-Identifier: GPL-2.0-only

#include <fcntl.h>
#include <linux/mempolicy.h>
#include <numa.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "../kselftest_harness.h"

int memfd_restricted(int flags, int fd)
{
	return syscall(__NR_memfd_restricted, flags, fd);
}

int memfd_restricted_bind(
	int fd, loff_t offset, unsigned long len, unsigned long mode,
	const unsigned long *nmask, unsigned long maxnode, unsigned int flags)
{
	struct file_range range = {
		.offset = offset,
		.len = len,
	};

	return syscall(__NR_memfd_restricted_bind, fd, &range, mode, nmask, maxnode, flags);
}

int memfd_restricted_bind_node(
	int fd, loff_t offset, unsigned long len,
	unsigned long mode, int node, unsigned int flags)
{
	int ret;
	struct bitmask *mask = numa_allocate_nodemask();

	numa_bitmask_setbit(mask, node);

	ret = memfd_restricted_bind(fd, offset, len, mode, mask->maskp, mask->size, flags);

	numa_free_nodemask(mask);

	return ret;
}

/**
 * Allocates a page in restrictedmem_fd, reads the node that the page was
 * allocated it and returns it. Returns -1 on error.
 */
int read_node(int restrictedmem_fd, unsigned long offset)
{
	int ret;
	int fd;

	fd = open("/proc/restrictedmem", O_RDWR);
	if (!fd)
		return -ENOTSUP;

	ret = ioctl(fd, restrictedmem_fd, offset);

	close(fd);

	return ret;
}

bool restrictedmem_testmod_loaded(void)
{
	struct stat buf;

	return stat("/proc/restrictedmem", &buf) == 0;
}

FIXTURE(restrictedmem_file)
{
	int fd;
	size_t page_size;
};

FIXTURE_SETUP(restrictedmem_file)
{
	int fd;
	int ret;
	struct stat stat;

	fd = memfd_restricted(0, -1);
	ASSERT_GT(fd, 0);

#define RESTRICTEDMEM_TEST_NPAGES 16
	ret = ftruncate(fd, getpagesize() * RESTRICTEDMEM_TEST_NPAGES);
	ASSERT_EQ(ret, 0);

	ret = fstat(fd, &stat);
	ASSERT_EQ(ret, 0);

	self->fd = fd;
	self->page_size = stat.st_blksize;
};

FIXTURE_TEARDOWN(restrictedmem_file)
{
	int ret;

	ret = close(self->fd);
	EXPECT_EQ(ret, 0);
}

#define ASSERT_REQUIREMENTS()					\
	do {							\
		struct bitmask *mask = numa_get_membind();	\
		ASSERT_GT(numa_num_configured_nodes(), 1);	\
		ASSERT_TRUE(numa_bitmask_isbitset(mask, 0));	\
		ASSERT_TRUE(numa_bitmask_isbitset(mask, 1));	\
		numa_bitmask_free(mask);			\
		ASSERT_TRUE(restrictedmem_testmod_loaded());	\
	} while (0)

TEST_F(restrictedmem_file, memfd_restricted_bind_works_as_expected)
{
	int ret;
	int node;
	int i;
	int node_bindings[] = { 1, 0, 1, 0, 1, 1, 0, 1 };

	ASSERT_REQUIREMENTS();

	for (i = 0; i < ARRAY_SIZE(node_bindings); i++) {
		ret = memfd_restricted_bind_node(
			self->fd, i * self->page_size, self->page_size,
			MPOL_BIND, node_bindings[i], 0);
		ASSERT_EQ(ret, 0);
	}

	for (i = 0; i < ARRAY_SIZE(node_bindings); i++) {
		node = read_node(self->fd, i * self->page_size);
		ASSERT_EQ(node, node_bindings[i]);
	}
}

TEST_HARNESS_MAIN
