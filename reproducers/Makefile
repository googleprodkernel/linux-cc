CC = gcc
CFLAGS = -Wall -O2 -static
TARGETS = subpool_shared_leak hugetlb_reserve_pages_out_put_pages

all: $(TARGETS)

subpool_shared_leak: subpool_shared_leak.c
	$(CC) $(CFLAGS) $< -o $@

hugetlb_reserve_pages_out_put_pages: hugetlb_reserve_pages_out_put_pages.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
