// SPDX-License-Identifier: Apache-2.0

package com.postman.insights.agent.benchmarks;

import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

/**
 * Microbenchmark for the per-call overhead the Postman Insights Java agent
 * adds when intercepting {@link SSLEngine#wrap(ByteBuffer, ByteBuffer)}.
 *
 * <p>What this benchmark measures, and what it does NOT:
 *
 * <ul>
 *   <li>It measures the cost of {@code Hooks.afterWrap2(...)} — the
 *       agent-controlled code path that the &#64;Advice inlines into every
 *       SSLEngine call. That code reads bytes out of the source
 *       ByteBuffer, builds a packed packet, and issues an ioctl(2) via
 *       JNI to push the bytes into the kernel ringbuf.</li>
 *   <li>It does NOT measure {@code SSLEngine.wrap} itself. The SSL
 *       handshake setup for a self-contained benchmark requires a real
 *       cert; that ceremony is the test harness's cost, not ours.
 *       The SSL wrap cost is well-characterised at ~10-50&nbsp;µs/op for
 *       typical TLS workloads — orders of magnitude larger than our
 *       overhead, so percentage-wise the agent is in the noise.</li>
 *   <li>It does NOT measure the kprobe path. When the kernel-side BPF
 *       program is loaded (the production case), the ioctl returns
 *       slightly faster (kernel handler runs the BPF program and
 *       returns). When NOT loaded (this benchmark's environment), the
 *       ioctl returns immediately with -ENOTTY. The user-space cost is
 *       similar; the difference is entirely on the kernel side and is
 *       already characterised in phase 5a.</li>
 * </ul>
 *
 * <p>The benchmark is parameterised by {@code payloadSize} to expose how
 * the per-call overhead scales with the size of the bytes the agent must
 * copy out of the ByteBuffer.
 */
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 3)
@Fork(2)
@State(Scope.Thread)
public class PostmanAgentBenchmark {

    /** Plaintext payload size to copy on each iteration. */
    @Param({"64", "1024", "16384"})
    public int payloadSize;

    private SSLEngine engineRef;        // used only for identityHashCode
    private ByteBuffer buf;
    private SSLEngineResult result;

    @Setup(Level.Trial)
    public void setupTrial() throws Exception {
        // We don't perform a handshake; Hooks.afterWrap2 only calls
        // System.identityHashCode(engine), nothing else on the engine.
        SSLContext ctx = SSLContext.getDefault();
        engineRef = ctx.createSSLEngine();

        buf = ByteBuffer.allocate(payloadSize);
        byte[] fill = new byte[payloadSize];
        for (int i = 0; i < fill.length; i++) {
            fill[i] = (byte) (i & 0xff);
        }
        buf.put(fill);
        buf.flip();
        // buf is now position=0, limit=payloadSize, ready for Hooks to read.

        // Hooks.afterWrap2 reads result.bytesConsumed() to know how much
        // of the buffer to copy. We pretend the whole buffer was consumed.
        result = new SSLEngineResult(
                SSLEngineResult.Status.OK,
                SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                payloadSize, // bytesConsumed
                0);          // bytesProduced
    }

    @Setup(Level.Invocation)
    public void resetBuffer() {
        // Hooks.afterWrap2 ADVANCES the buffer's position as a side effect
        // of readBytes(). Reset between invocations so each call sees the
        // same starting state.
        buf.position(payloadSize).limit(payloadSize);
    }

    // -- BENCHMARK 1: the actual agent per-call cost ----------------------

    /**
     * The hot path: Hooks.afterWrap2 with realistic inputs. The published
     * "per-call overhead" of the agent is this number, in ns/op.
     */
    @Benchmark
    public void hooksAfterWrap(Blackhole bh) {
        com.postman.insights.agent.instrumentations.SSLEngineInst.Hooks.afterWrap2(
                engineRef, buf, result, 0);
        bh.consume(buf);
    }

    // -- BENCHMARK 2: baseline (no agent code) ----------------------------

    /**
     * What the same caller pays without the agent: just the ByteBuffer
     * accounting any reasonable callback would have to do (a position
     * read + a no-op consume). Subtracting this from hooksAfterWrap
     * gives the cleanest "added by the agent" figure.
     */
    @Benchmark
    public void baselineNoAgent(Blackhole bh) {
        int pos = buf.position();
        bh.consume(pos);
        bh.consume(result);
    }
}
