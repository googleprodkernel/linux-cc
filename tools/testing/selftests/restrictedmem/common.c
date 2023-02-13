// SPDX-License-Identifier: GPL-2.0-only

#include <sys/syscall.h>
#include <unistd.h>

int memfd_restricted(unsigned int flags, char *mount_path)
{
	return syscall(__NR_memfd_restricted, flags, mount_path);
}
