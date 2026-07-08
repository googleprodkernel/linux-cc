CC = gcc
CFLAGS = -Wall -O2 -static
TARGETS = subpool_shared_leak

all: $(TARGETS)

subpool_shared_leak: subpool_shared_leak.c
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGETS)

.PHONY: all clean
