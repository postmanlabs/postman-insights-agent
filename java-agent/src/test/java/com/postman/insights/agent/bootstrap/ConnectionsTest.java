package com.postman.insights.agent.bootstrap;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

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

    @Test
    void doesNotKeepEnginesAlive() throws Exception {
        Connections c = new Connections();
        for (int i = 0; i < 1000; i++) {
            c.get(new Object());
        }
        for (int i = 0; i < 50 && c.size() > 0; i++) {
            System.gc();
            Thread.sleep(20);
        }
        assertEquals(0, c.size());
    }
}
