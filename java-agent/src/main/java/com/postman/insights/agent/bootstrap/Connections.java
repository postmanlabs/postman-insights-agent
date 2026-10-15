package com.postman.insights.agent.bootstrap;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Assigns each engine a connection id that is unique for the life of the JVM,
 * without keeping the engine alive.
 *
 * <p>Keys are compared by identity, not {@code equals}, because an engine
 * subclass could override {@code equals} and {@code hashCode}. Ids come from a
 * counter, not {@code System.identityHashCode}, which can collide.
 */
final class Connections {
    /** Per-connection state the bridge caches. */
    static final class Info {
        final long id;
        /** Frame flags describing the role, or 0 until the role is known. */
        volatile short roleFlags;
        /**
         * Whether an engine's RECV, and SEND, frame was sent. The kernel ties
         * a connection to its socket at a RECV frame, from the socket the
         * thread just read, or after a SEND frame, at the thread's next
         * socket write. The first of each comes at the first unwrap and wrap,
         * in the handshake, so the tie exists before any request or response.
         */
        volatile boolean recvSent;
        volatile boolean sendSent;
        /**
         * The address epoch (see Bridge) in which a blocking socket's ADDRESS
         * frame was last sent, or -1: the kernel takes a socket's addresses
         * from it rather than from its thread's reads.
         */
        volatile int addressEpoch = -1;

        /**
         * Which directions the engine reported CLOSED for, whether a thread is
         * sending CLOSE, and whether CLOSE was written. Guarded by this.
         */
        private boolean inboundDone;
        private boolean outboundDone;
        private boolean closeSending;
        private boolean closeSent;
        /**
         * A socket's stream calls in flight, and whether a CLOSE that was due
         * waits for them. Guarded by this.
         */
        private int streamsInFlight;
        private boolean closeDeferred;

        Info(long id) {
            this.id = id;
        }

        /**
         * Records that the engine reported CLOSED for one direction, and
         * returns true when the connection can carry no more responses and a
         * CLOSE frame should be sent: when the side that carries responses is
         * done (the server's outbound, the client's inbound), or both sides
         * are when the role is unknown. The request side alone is not enough:
         * a server still answers a request whose client closed its side
         * after sending it.
         *
         * <p>It returns true to one caller at a time, which must report
         * whether it wrote the frame with {@link #closeAttempted}; until one
         * has, a later CLOSED result retries.
         */
        synchronized boolean closed(boolean outbound, short role) {
            if (closeSent || closeSending) {
                return false;
            }
            if (outbound) {
                outboundDone = true;
            } else {
                inboundDone = true;
            }
            boolean responsesDone;
            if ((role & Frame.FLAG_ROLE_KNOWN) == 0) {
                responsesDone = inboundDone && outboundDone;
            } else if ((role & Frame.FLAG_CLIENT_MODE) != 0) {
                responsesDone = inboundDone;
            } else {
                responsesDone = outboundDone;
            }
            closeSending = responsesDone;
            return responsesDone;
        }

        /** A socket stream call started. */
        synchronized void streamEntered() {
            streamsInFlight++;
        }

        /**
         * A socket stream call ended, its frame sent; true when it was the
         * last in flight and a CLOSE waited for it, which the caller then
         * sends (and reports with {@link #closeAttempted}).
         */
        synchronized boolean streamExited() {
            if (--streamsInFlight == 0 && closeDeferred) {
                closeDeferred = false;
                return true;
            }
            return false;
        }

        /**
         * A CLOSE is due ({@link #closed} returned true): true when other
         * stream calls are in flight, the last of which sends it; false when
         * the caller sends it now. inFlight: the caller is a stream call
         * itself (a read that reached the end of the stream).
         */
        synchronized boolean deferClose(boolean inFlight) {
            if (streamsInFlight > (inFlight ? 1 : 0)) {
                closeDeferred = true;
                return true;
            }
            return false;
        }

        /** Ends the attempt {@link #closed} started: written, or to retry. */
        synchronized void closeAttempted(boolean written) {
            closeSending = false;
            closeSent = written;
        }
    }

    private final ConcurrentHashMap<Object, Info> map = new ConcurrentHashMap<Object, Info>();
    private final ReferenceQueue<Object> queue = new ReferenceQueue<Object>();
    /**
     * Ids count up from a random start in [1, 2^62): a JVM that reuses an
     * exited one's PID must not reuse its ids, which the Insights agent
     * keys connections by, with the PID. ThreadLocalRandom, not
     * SecureRandom, which can block for entropy at JVM start.
     */
    private final AtomicLong nextId = new AtomicLong(ThreadLocalRandom.current().nextLong(1, 1L << 62));

    Info get(Object engine) {
        return get(engine, new Lookup());
    }

    /**
     * Like {@link #get(Object)}, using {@code scratch} (owned by the calling
     * thread) as the lookup key, so a lookup allocates nothing.
     */
    Info get(Object engine, Lookup scratch) {
        Info info = find(engine, scratch);
        if (info != null) {
            return info;
        }
        expunge();
        Info fresh = new Info(nextId.getAndIncrement());
        Info prev = map.putIfAbsent(new Key(engine, queue), fresh);
        return prev != null ? prev : fresh;
    }

    /** The connection's state, or null when it was never seen. */
    Info find(Object engine, Lookup scratch) {
        scratch.referent = engine;
        try {
            return map.get(scratch);
        } finally {
            scratch.referent = null;
        }
    }

    int size() {
        expunge();
        return map.size();
    }

    /** Tests only: the weak reference the map holds for engine, or null. */
    Reference<Object> referenceFor(Object engine) {
        for (Map.Entry<Object, Info> e : map.entrySet()) {
            Key k = (Key) e.getKey();
            if (k.get() == engine) {
                return k;
            }
        }
        return null;
    }

    private void expunge() {
        for (Object ref; (ref = queue.poll()) != null; ) {
            map.remove(ref);
        }
    }

    /** Stored key: weak, identity-compared, hash fixed at creation. */
    private static final class Key extends WeakReference<Object> {
        private final int hash;

        Key(Object referent, ReferenceQueue<Object> q) {
            super(referent, q);
            hash = System.identityHashCode(referent);
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            Object mine = get();
            if (mine == null) {
                return false;
            }
            if (o instanceof Key) {
                return mine == ((Key) o).get();
            }
            return o instanceof Lookup && mine == ((Lookup) o).referent;
        }
    }

    /**
     * Lookup-only key, so a lookup allocates no WeakReference. Never stored in
     * the map, so it can be reused.
     */
    static final class Lookup {
        Object referent;

        @Override
        public int hashCode() {
            return System.identityHashCode(referent);
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof Key) {
                return referent == ((Key) o).get();
            }
            return o instanceof Lookup && referent == ((Lookup) o).referent;
        }
    }
}
