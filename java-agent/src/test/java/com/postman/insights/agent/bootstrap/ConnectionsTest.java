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
    void comparesByIdentityNotEquals() {
        Connections c = new Connections();
        long a = c.get(new EqualEngine()).id;
        long b = c.get(new EqualEngine()).id;
        assertNotEquals(a, b);
    }

    @Test
    void idsAreSequentialFromOne() {
        Connections c = new Connections();
        assertEquals(1, c.get(new Object()).id);
        assertEquals(2, c.get(new Object()).id);
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
