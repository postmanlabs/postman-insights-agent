package com.postman.insights.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.ref.Reference;
import java.lang.ref.WeakReference;

import org.junit.jupiter.api.Test;

class ConnectionsTest {
    /** Equal by value, as an engine subclass overriding equals could be. */
    private static final class EqualEngine {
        @Override
        public boolean equals(Object o) {
            return o instanceof EqualEngine;
        }

        @Override
        public int hashCode() {
            return 1;
        }
    }

    @Test
    void sameEngineSameId() {
        Connections c = new Connections();
        Object engine = new Object();
        assertSame(c.get(engine), c.get(engine));
    }

    @Test
    void scratchLookupKey() {
        Connections c = new Connections();
        Connections.Lookup scratch = new Connections.Lookup();
        Object engine = new Object();
        Connections.Info info = c.get(engine);
        assertSame(info, c.get(engine, scratch));
        assertNull(scratch.referent, "scratch key keeps the engine alive");
        assertNotEquals(info.id, c.get(new Object(), scratch).id);
    }

    @Test
    void comparesByIdentityNotEquals() {
        Connections c = new Connections();
        long a = c.get(new EqualEngine()).id;
        long b = c.get(new EqualEngine()).id;
        assertNotEquals(a, b);
    }

    @Test
    void idsAreSequential() {
        Connections c = new Connections();
        long first = c.get(new Object()).id;
        assertEquals(first + 1, c.get(new Object()).id);
    }

    /**
     * Each JVM's ids start at a random place below 2^62 (the kernel tags bit
     * 63), so a JVM that reuses an exited one's PID does not reuse its ids,
     * which the Insights agent keys connections by. Here two JVMs' worth.
     */
    @Test
    void eachJvmStartsAtARandomId() {
        long a = new Connections().get(new Object()).id;
        long b = new Connections().get(new Object()).id;
        assertNotEquals(a, b);
        for (long id : new long[] {a, b}) {
            assertTrue(id >= 1 && id < 1L << 62, Long.toString(id));
        }
    }

    /**
     * The map holds engines only weakly, and drops an entry once its reference
     * is enqueued, which is what the garbage collector does when the engine
     * becomes unreachable. Enqueuing by hand keeps this deterministic; a
     * System.gc() is not guaranteed to collect anything.
     */
    @Test
    void dropsEntriesOfCollectedEngines() {
        Connections c = new Connections();
        Object kept = new Object();
        Object collected = new Object();
        long keptId = c.get(kept).id;
        c.get(collected);

        Reference<Object> ref = c.referenceFor(collected);
        assertTrue(ref instanceof WeakReference, "engine held strongly");
        assertSame(collected, ref.get());

        assertTrue(ref.enqueue());
        assertEquals(1, c.size());
        assertNull(c.referenceFor(collected));
        assertEquals(keptId, c.get(kept).id);
    }
}
