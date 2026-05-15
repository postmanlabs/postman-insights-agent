# SPDX-License-Identifier: Apache-2.0
#
# JNI shim build for the postman-java-agent (Phase 5b.1).
#
# JAVA_HOME must be set; the dev container's Dockerfile does this. On
# Debian-derived hosts, `default-jdk` or `openjdk-17-jdk-headless` ships
# jni.h at $JAVA_HOME/include/jni.h.

CC      ?= cc
CFLAGS  ?= -O2 -fPIC -Wall -Wextra -Werror -g
LDFLAGS ?= -shared
INCLUDES = -I"$(JAVA_HOME)/include" -I"$(JAVA_HOME)/include/linux"

BUILD_DIR := build
LIB       := $(BUILD_DIR)/libpostman_jni.so

.PHONY: all clean

all: $(LIB)

$(BUILD_DIR):
	mkdir -p $@

$(LIB): postman_jni.c | $(BUILD_DIR)
	@if [ -z "$(JAVA_HOME)" ]; then echo "JAVA_HOME is not set"; exit 1; fi
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $<

clean:
	rm -rf $(BUILD_DIR)
