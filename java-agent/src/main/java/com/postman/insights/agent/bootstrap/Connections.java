package com.postman.insights.agent.bootstrap;

import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.lang.ref.WeakReference;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
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
         * Which directions the engine reported CLOSED for, whether a thread is
         * sending CLOSE, and whether CLOSE was written. Guarded by this.
         */
        private boolean inboundDone;
        private boolean outboundDone;
        private boolean closeSending;
        private boolean closeSent;

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

        /** Ends the attempt {@link #closed} started: written, or to retry. */
        synchronized void closeAttempted(boolean written) {
            closeSending = false;
            closeSent = written;
        }
    }

    private final ConcurrentHashMap<Object, Info> map = new ConcurrentHashMap<Object, Info>();
    private final ReferenceQueue<Object> queue = new ReferenceQueue<Object>();
    private final AtomicLong nextId = new AtomicLong(1);

    Info get(Object engine) {
        return get(engine, new Lookup());
    }

    /**
     * Like {@link #get(Object)}, using {@code scratch} (owned by the calling
     * thread) as the lookup key, so a lookup allocates nothing.
     */
    Info get(Object engine, Lookup scratch) {
        scratch.referent = engine;
        Info info;
        try {
            info = map.get(scratch);
        } finally {
            scratch.referent = null;
        }
        if (info != null) {
            return info;
        }
        expunge();
        Info fresh = new Info(nextId.getAndIncrement());
        Info prev = map.putIfAbsent(new Key(engine, queue), fresh);
        return prev != null ? prev : fresh;
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
