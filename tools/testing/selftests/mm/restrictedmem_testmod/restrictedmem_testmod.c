// SPDX-License-Identifier: GPL-2.0-only

#include "linux/printk.h"
#include "linux/types.h"
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/restrictedmem.h>

MODULE_DESCRIPTION("A kernel module to support restrictedmem testing");
MODULE_AUTHOR("ackerleytng@google.com");
MODULE_LICENSE("GPL");

void dummy_op(struct restrictedmem_notifier *notifier, pgoff_t start, pgoff_t end)
{
}

static const struct restrictedmem_notifier_ops dummy_notifier_ops = {
	.invalidate_start = dummy_op,
	.invalidate_end = dummy_op,
	.error = dummy_op,
};

static struct restrictedmem_notifier dummy_notifier = {
	.ops = &dummy_notifier_ops,
};

static long restrictedmem_testmod_ioctl(
	struct file *file, unsigned int cmd, unsigned long offset)
{
	long ret;
	struct fd f;
	struct page *page;
	pgoff_t start = offset >> PAGE_SHIFT;

	f = fdget(cmd);
	if (!f.file)
		return -EBADF;

	ret = -EINVAL;
	if (!file_is_restrictedmem(f.file))
		goto out;


	ret = restrictedmem_bind(f.file, start, start + 1, &dummy_notifier, true);
	if (ret)
		goto out;

	ret = restrictedmem_get_page(f.file, (unsigned long)start, &page, NULL);
	if (ret)
		goto out;

	ret = page_to_nid(page);

	folio_put(page_folio(page));

	restrictedmem_unbind(f.file, start, start + 1, &dummy_notifier);

out:
	fdput(f);

	return ret;
}

static const struct proc_ops restrictedmem_testmod_ops = {
	.proc_ioctl = restrictedmem_testmod_ioctl,
};

static struct proc_dir_entry *restrictedmem_testmod_entry;

static int restrictedmem_testmod_init(void)
{
	restrictedmem_testmod_entry = proc_create(
		"restrictedmem", 0660, NULL, &restrictedmem_testmod_ops);

	return 0;
}

static void restrictedmem_testmod_exit(void)
{
	proc_remove(restrictedmem_testmod_entry);
}

module_init(restrictedmem_testmod_init);
module_exit(restrictedmem_testmod_exit);
