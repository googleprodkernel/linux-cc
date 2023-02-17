// SPDX-License-Identifier: GPL-2.0-only

#include "linux/limits.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>

#include "linux/restrictedmem.h"

#include "common.h"
#include "../kselftest_harness.h"

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

static int set_shmem_thp_policy(char *policy)
{
	FILE *fp;
	size_t len = strlen(policy);
	int ret = -1;

	if (!is_valid_shmem_thp_policy(policy))
		return ret;

	fp = fopen("/sys/kernel/mm/transparent_hugepage/shmem_enabled", "w");
	if (!fp)
		return ret;

	if (fwrite(policy, 1, len, fp) != len)
		goto out;

	if (fwrite("\n", 1, 1, fp) != 1)
		goto out;

	ret = 0;

out:
	fclose(fp);
	return ret;
}

FIXTURE(reset_shmem_enabled)
{
	/*
	 * Expect shmem_enabled to be one of always, within_size, advise, never,
	 * deny, force
	 */
	char shmem_enabled[12];
};

FIXTURE_SETUP(reset_shmem_enabled)
{
	memset(self->shmem_enabled, 0, 12);
	ASSERT_EQ(0, get_shmem_thp_policy(self->shmem_enabled));
}

FIXTURE_TEARDOWN(reset_shmem_enabled)
{
	ASSERT_EQ(0, set_shmem_thp_policy(self->shmem_enabled));
}

TEST_F(reset_shmem_enabled, restrictedmem_fstat_shmem_enabled_never)
{
	int mfd = -1;
	struct stat stat;
	char *orig_shmem_enabled;

	ASSERT_EQ(0, set_shmem_thp_policy("never"));

	mfd = memfd_restricted(0, NULL);
	ASSERT_NE(-1, mfd);

	ASSERT_EQ(0, fstat(mfd, &stat));

	/*
	 * st_blksize is set based on the superblock's s_blocksize_bits. For
	 * shmem, this is set to PAGE_SHIFT
	 */
	ASSERT_EQ(stat.st_blksize, getpagesize());

	close(mfd);
}

TEST_F(reset_shmem_enabled, restrictedmem_fstat_shmem_enabled_always)
{
	int mfd = -1;
	struct stat stat;
	char *orig_shmem_enabled;

	ASSERT_EQ(0, set_shmem_thp_policy("always"));

	mfd = memfd_restricted(0, NULL);
	ASSERT_NE(-1, mfd);

	ASSERT_EQ(0, fstat(mfd, &stat));

	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	close(mfd);
}

TEST(restrictedmem_invalid_flags)
{
	int mfd = memfd_restricted(99, NULL);

	ASSERT_EQ(-1, mfd);
	ASSERT_EQ(EINVAL, errno);
}

TEST_F(reset_shmem_enabled, restrictedmem_rmfd_hugepage)
{
	int mfd = -1;
	struct stat stat;

	ASSERT_EQ(0, set_shmem_thp_policy("never"));

	mfd = memfd_restricted(RMFD_HUGEPAGE, NULL);
	ASSERT_NE(-1, mfd);

	ASSERT_EQ(0, fstat(mfd, &stat));

	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	close(mfd);
}

TEST(restrictedmem_tmpfile_no_mount_path)
{
	int mfd = memfd_restricted(RMFD_TMPFILE, NULL);

	ASSERT_EQ(-1, mfd);
	ASSERT_EQ(EINVAL, errno);
}

TEST(restrictedmem_tmpfile_nonexistent_mount_path)
{
	int mfd = memfd_restricted(RMFD_TMPFILE,
				   "/nonexistent/nonexistent/nonexistent");

	ASSERT_EQ(-1, mfd);
	ASSERT_EQ(ENOENT, errno);
}

TEST(restrictedmem_tmpfile_not_tmpfs_mount)
{
	int mfd = memfd_restricted(RMFD_TMPFILE, "/proc");

	ASSERT_EQ(-1, mfd);
	ASSERT_EQ(EINVAL, errno);
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
	ASSERT_EQ(0, ret);
}

TEST_F(tmpfs_hugepage_mount_path, restrictedmem_fstat_tmpfs_huge_always)
{
	int ret = -1;
	int mfd = -1;
	struct stat stat;

	ret = mount("name", self->mount_path, "tmpfs", 0, "huge=always");
	ASSERT_EQ(0, ret);

	mfd = memfd_restricted(RMFD_TMPFILE, self->mount_path);
	ASSERT_NE(-1, mfd);

	ret = fstat(mfd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	close(mfd);
}

TEST_F(tmpfs_hugepage_mount_path, restrictedmem_fstat_tmpfs_huge_never)
{
	int ret = -1;
	int mfd = -1;
	struct stat stat;

	ret = mount("name", self->mount_path, "tmpfs", 0, "huge=never");
	ASSERT_EQ(0, ret);

	mfd = memfd_restricted(RMFD_TMPFILE, self->mount_path);
	ASSERT_NE(-1, mfd);

	ret = fstat(mfd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, getpagesize());

	close(mfd);
}

TEST_F(tmpfs_hugepage_mount_path, restrictedmem_umount_rmdir_while_file_open)
{
	int ret = -1;
	int mfd = -1;

	ret = mount("name", self->mount_path, "tmpfs", 0, "huge=always");
	ASSERT_EQ(0, ret);

	mfd = memfd_restricted(RMFD_TMPFILE, self->mount_path);
	ASSERT_NE(-1, mfd);

	ret = umount2(self->mount_path, MNT_FORCE);
	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EBUSY, errno);

	ret = rmdir(self->mount_path);
	ASSERT_EQ(-1, ret);
	ASSERT_EQ(EBUSY, errno);

	close(mfd);
}

TEST_F(tmpfs_hugepage_mount_path, restrictedmem_provide_mount_subdir)
{
	int ret = -1;
	int mfd = -1;
	struct stat stat;
	char subdir_path[PATH_MAX] = {0};

	ret = mount("name", self->mount_path, "tmpfs", 0, "huge=always");
	ASSERT_EQ(0, ret);

	snprintf(subdir_path, PATH_MAX, "%s/%s", self->mount_path, "subdir");
	ret = mkdir(subdir_path, 0777);
	ASSERT_EQ(0, ret);

	/*
	 * Any subdirectory of a tmpfs mount can be provided to memfd_restricted
	 * as a reference to a mount
	 */
	mfd = memfd_restricted(RMFD_TMPFILE, subdir_path);
	ASSERT_NE(-1, mfd);

	ret = fstat(mfd, &stat);
	ASSERT_EQ(0, ret);
	ASSERT_EQ(stat.st_blksize, get_hpage_pmd_size());

	/*
	 * shmem file is created at the mount, so the subdirectory can be
	 * removed without issues.
	 */
	ret = rmdir(subdir_path);
	ASSERT_EQ(0, ret);

	close(mfd);
}

TEST_HARNESS_MAIN
