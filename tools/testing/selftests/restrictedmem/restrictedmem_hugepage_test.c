// SPDX-License-Identifier: GPL-2.0-only

#define _GNU_SOURCE /* for O_PATH */
#define _POSIX_C_SOURCE /* for PATH_MAX */
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "linux/restrictedmem.h"

#include "common.h"
#include "../kselftest_harness.h"

/*
 * Expect policy to be one of always, within_size, advise, never,
 * deny, force
 */
#define POLICY_BUF_SIZE 12

static int get_hpage_pmd_size(void)
{
	FILE *fp;
	char buf[100];
	char *ret;
	int size;

	fp = fopen("/sys/kernel/mm/transparent_hugepage/hpage_pmd_size", "r");
	if (!fp)
		return -1;

	ret = fgets(buf, 100, fp);
	if (ret != buf) {
		size = -1;
		goto out;
	}

	if (sscanf(buf, "%d\n", &size) != 1)
		size = -1;

out:
	fclose(fp);

	return size;
}

static bool is_valid_shmem_thp_policy(char *policy)
{
	if (strcmp(policy, "always") == 0)
		return true;
	if (strcmp(policy, "within_size") == 0)
		return true;
	if (strcmp(policy, "advise") == 0)
		return true;
	if (strcmp(policy, "never") == 0)
		return true;
	if (strcmp(policy, "deny") == 0)
		return true;
	if (strcmp(policy, "force") == 0)
		return true;

	return false;
}

static int get_shmem_thp_policy(char *policy)
{
	FILE *fp;
	char buf[100];
	char *left = NULL;
	char *right = NULL;
	int ret = -1;

	fp = fopen("/sys/kernel/mm/transparent_hugepage/shmem_enabled", "r");
	if (!fp)
		return -1;

	if (fgets(buf, 100, fp) != buf)
		goto out;

	/*
	 * Expect shmem_enabled to be of format like "always within_size advise
	 * [never] deny force"
	 */
	left = memchr(buf, '[', 100);
	if (!left)
		goto out;

	right = memchr(buf, ']', 100);
	if (!right)
		goto out;

	memcpy(policy, left + 1, right - left - 1);

	ret = !is_valid_shmem_thp_policy(policy);

out:
	fclose(fp);
	return ret;
}

static int write_string_to_file(const char *path, const char *string)
{
	FILE *fp;
	size_t len = strlen(string);
	int ret = -1;

	fp = fopen(path, "w");
	if (!fp)
		return ret;

	if (fwrite(string, 1, len, fp) != len)
		goto out;

	ret = 0;

out:
	fclose(fp);
	return ret;
}

static int set_shmem_thp_policy(char *policy)
{
	int ret = -1;
	/* +1 for newline */
	char to_write[POLICY_BUF_SIZE + 1] = { 0 };

	if (!is_valid_shmem_thp_policy(policy))
		return ret;

	ret = snprintf(to_write, POLICY_BUF_SIZE + 1, "%s\n", policy);
	if (ret != strlen(policy) + 1)
		return -1;

	ret = write_string_to_file(
		"/sys/kernel/mm/transparent_hugepage/shmem_enabled", to_write);

	return ret;
}

FIXTURE(reset_shmem_enabled)
{
	char shmem_enabled[POLICY_BUF_SIZE];
};

FIXTURE_SETUP(reset_shmem_enabled)
{
	memset(self->shmem_enabled, 0, POLICY_BUF_SIZE);
	ASSERT_EQ(0, get_shmem_thp_policy(self->shmem_enabled));
}

FIXTURE_TEARDOWN(reset_shmem_enabled)
{
	ASSERT_EQ(0, set_shmem_thp_policy(self->shmem_enabled));
}

TEST_F(reset_shmem_enabled, restrictedmem_fstat_shmem_enabled_never)
{
	int fd = -1;
	struct stat stat;

	ASSERT_EQ(0, set_shmem_thp_policy("never"));

	fd = memfd_restricted(0, -1);
	ASSERT_NE(-1, fd);

	ASSERT_EQ(0, fstat(fd, &stat));

	/*
	 * st_blksize is set based on the superblock's s_blocksize_bits. For
	 * shmem, this is set to PAGE_SHIFT
	 */
	ASSERT_EQ(stat.st_blksize, getpagesize());

	close(fd);
}

TEST_F(reset_shmem_enabled, restrictedmem_fstat_shmem_enabled_always)
{
	int fd = -1;
	struct stat stat;

	ASSERT_EQ(0, set_shmem_thp_policy("always"));

	fd = memfd_restricted(0, -1);
	ASSERT_NE(-1, fd);

	ASSERT_EQ(0, fstat(fd, &stat));

	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	close(fd);
}

TEST(restrictedmem_tmpfile_invalid_fd)
{
	int fd = memfd_restricted(RMFD_TMPFILE, -2);

	ASSERT_EQ(-1, fd);
	ASSERT_EQ(EINVAL, errno);
}

TEST(restrictedmem_tmpfile_fd_not_a_mount)
{
	int fd = memfd_restricted(RMFD_TMPFILE, STDOUT_FILENO);

	ASSERT_EQ(-1, fd);
	ASSERT_EQ(EINVAL, errno);
}

TEST(restrictedmem_tmpfile_not_tmpfs_mount)
{
	int fd = -1;
	int mfd = -1;

	mfd = open("/proc", O_PATH);
	ASSERT_NE(-1, mfd);

	fd = memfd_restricted(RMFD_TMPFILE, mfd);

	ASSERT_EQ(-1, fd);
	ASSERT_EQ(EINVAL, errno);
}

FIXTURE(tmpfs_hugepage_sfd)
{
	int sfd;
};

FIXTURE_SETUP(tmpfs_hugepage_sfd)
{
	self->sfd = fsopen("tmpfs", 0);
	ASSERT_NE(-1, self->sfd);
}

FIXTURE_TEARDOWN(tmpfs_hugepage_sfd)
{
	close(self->sfd);
}

TEST_F(tmpfs_hugepage_sfd, restrictedmem_fstat_tmpfs_huge_always)
{
	int ret = -1;
	int fd = -1;
	int mfd = -1;
	struct stat stat;

	fsconfig(self->sfd, FSCONFIG_SET_STRING, "huge", "always", 0);
	fsconfig(self->sfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);

	mfd = fsmount(self->sfd, 0, 0);
	ASSERT_NE(-1, mfd);

	fd = memfd_restricted(RMFD_TMPFILE, mfd);
	ASSERT_NE(-1, fd);

	/* User can close reference to mount */
	ret = close(mfd);
	ASSERT_EQ(0, ret);

	ret = fstat(fd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	close(fd);
}

TEST_F(tmpfs_hugepage_sfd, restrictedmem_fstat_tmpfs_huge_never)
{
	int ret = -1;
	int fd = -1;
	int mfd = -1;
	struct stat stat;

	fsconfig(self->sfd, FSCONFIG_SET_STRING, "huge", "never", 0);
	fsconfig(self->sfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);

	mfd = fsmount(self->sfd, 0, 0);
	ASSERT_NE(-1, mfd);

	fd = memfd_restricted(RMFD_TMPFILE, mfd);
	ASSERT_NE(-1, fd);

	/* User can close reference to mount */
	ret = close(mfd);
	ASSERT_EQ(0, ret);

	ret = fstat(fd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, getpagesize());

	close(fd);
}

static bool directory_exists(const char *path)
{
	struct stat sb;

	return stat(path, &sb) == 0 && S_ISDIR(sb.st_mode);
}

FIXTURE(tmpfs_hugepage_mount_path)
{
	char *mount_path;
};

FIXTURE_SETUP(tmpfs_hugepage_mount_path)
{
	int ret = -1;

	/* /tmp is an FHS-mandated world-writable directory */
	self->mount_path = "/tmp/restrictedmem-selftest-mnt";

	if (!directory_exists(self->mount_path)) {
		ret = mkdir(self->mount_path, 0777);
		ASSERT_EQ(0, ret);
	}
}

FIXTURE_TEARDOWN(tmpfs_hugepage_mount_path)
{
	int ret = -1;

	if (!directory_exists(self->mount_path))
		return;

	ret = umount2(self->mount_path, MNT_FORCE);
	EXPECT_EQ(0, ret);
	if (ret == -1 && errno == EINVAL)
		fprintf(stderr, "%s was not mounted\n", self->mount_path);

	ret = rmdir(self->mount_path);
	EXPECT_EQ(0, ret);
	if (ret == -1)
		fprintf(stderr, "rmdir(%s) failed\n", self->mount_path);
}

/*
 * When the restrictedmem's fd is open, a user should not be able to unmount or
 * remove the mounted directory
 */
TEST_F(tmpfs_hugepage_mount_path, restrictedmem_umount_rmdir_while_file_open)
{
	int ret = -1;
	int fd = -1;
	int mfd = -1;
	struct stat stat;

	ret = mount("name", self->mount_path, "tmpfs", 0, "huge=always");
	ASSERT_EQ(0, ret);

	mfd = open(self->mount_path, O_PATH);
	ASSERT_NE(-1, mfd);

	fd = memfd_restricted(RMFD_TMPFILE, mfd);
	ASSERT_NE(-1, fd);

	/* We don't need this reference to the mount anymore */
	ret = close(mfd);
	ASSERT_EQ(0, ret);

	/* restrictedmem's fd should still be usable */
	ret = fstat(fd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	/* User should not be able to unmount directory */
	ret = umount2(self->mount_path, MNT_FORCE);
	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EBUSY, errno);

	ret = rmdir(self->mount_path);
	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EBUSY, errno);

	close(fd);
}

/* The fd of a file on the mount can be provided as mount_fd */
TEST_F(tmpfs_hugepage_mount_path, restrictedmem_provide_fd_of_file)
{
	int ret = -1;
	int fd = -1;
	int ffd = -1;
	char tmp_file_path[PATH_MAX] = { 0 };
	struct stat stat;

	ret = mount("name", self->mount_path, "tmpfs", 0, "huge=always");
	ASSERT_EQ(0, ret);

	snprintf(tmp_file_path, PATH_MAX, "%s/tmp-file", self->mount_path);
	ret = write_string_to_file(tmp_file_path, "filler\n");
	ASSERT_EQ(0, ret);

	ffd = open(tmp_file_path, O_RDWR);
	ASSERT_NE(-1, ffd);

	fd = memfd_restricted(RMFD_TMPFILE, ffd);
	ASSERT_NE(-1, fd);

	/* We don't need this reference anymore */
	ret = close(ffd);
	ASSERT_EQ(0, ret);

	ret = fstat(fd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	close(fd);
	remove(tmp_file_path);
}

/*
 * The fd of any file on the mount (including subdirectories) can be provided as
 * mount_fd
 */
TEST_F(tmpfs_hugepage_mount_path, restrictedmem_provide_fd_of_file_in_subdir)
{
	int ret = -1;
	int fd = -1;
	int ffd = -1;
	char tmp_dir_path[PATH_MAX] = { 0 };
	char tmp_file_path[PATH_MAX] = { 0 };
	struct stat stat;

	ret = mount("name", self->mount_path, "tmpfs", 0, "huge=always");
	ASSERT_EQ(0, ret);

	snprintf(tmp_dir_path, PATH_MAX, "%s/tmp-subdir", self->mount_path);
	ret = mkdir(tmp_dir_path, 0777);
	ASSERT_EQ(0, ret);

	snprintf(tmp_file_path, PATH_MAX, "%s/tmp-subdir/tmp-file",
		 self->mount_path);
	ret = write_string_to_file(tmp_file_path, "filler\n");
	ASSERT_EQ(0, ret);

	ffd = open(tmp_file_path, O_RDWR);
	ASSERT_NE(-1, ffd);

	fd = memfd_restricted(RMFD_TMPFILE, ffd);
	ASSERT_NE(-1, fd);

	/* We don't need this reference anymore */
	ret = close(ffd);
	ASSERT_EQ(0, ret);

	ret = fstat(fd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	close(fd);
	remove(tmp_file_path);
	rmdir(tmp_dir_path);
}

TEST_HARNESS_MAIN
