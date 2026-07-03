// SPDX-License-Identifier: Apache-2.0
//
// Phase 5b.1 JNI shim — exposes a single native method `doIoctl(int fd,
// long cmd, long arg)` that wraps the `ioctl(2)` syscall. The Java side
// builds a packed `java_packet` struct in off-heap memory (matching the
// 41-byte layout in ebpf/programs/java_tls.bpf.c) and passes its address
// here. The `ioctl()` itself returns -1/ENOTTY (the kernel doesn't have
// a handler for our magic command); the eBPF kprobe runs first.
//
// Build:
//   make -f Makefile.jni
// Produces: build/libpostman_jni.so

#include <jni.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <errno.h>

/*
 * Mirrors:
 *   public static native int doIoctl(int fd, long cmd, long arg);
 * in com.postman.insights.agent.ebpf.NativeMemory.
 *
 * We deliberately return errno alongside rc via a 64-bit packing:
 *   high 32 bits = errno  (0 on success)
 *   low  32 bits = ioctl return value
 * Java side decodes. This lets the spike's main() print useful diagnostics
 * without an extra JNI call.
 */
JNIEXPORT jlong JNICALL
Java_com_postman_insights_agent_ebpf_NativeMemory_doIoctlNative(
        JNIEnv *env,
        jclass  clazz,
        jint    fd,
        jlong   cmd,
        jlong   arg) {
    (void) env;
    (void) clazz;
    errno = 0;
    int rc = ioctl((int) fd, (unsigned long) cmd, (void *) (uintptr_t) arg);
    int err = (rc < 0) ? errno : 0;
    return ((jlong)(uint32_t) err << 32) | (jlong)(uint32_t) rc;
}
