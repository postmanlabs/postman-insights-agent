# SPDX-License-Identifier: Apache-2.0
#
# Phase 5a harness for the java_tls eBPF kprobe.

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Werror -g
LDFLAGS ?=

BIN := harness

.PHONY: all clean

all: $(BIN)

$(BIN): harness.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BIN)
