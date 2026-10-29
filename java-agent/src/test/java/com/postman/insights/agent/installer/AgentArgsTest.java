package com.postman.insights.agent.installer;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AgentArgsTest {
    @Test
    void defaults() {
        assertEquals(16384, AgentArgs.parse(null).captureCap);
        assertEquals(16384, AgentArgs.parse("").captureCap);
    }

    @Test
    void capture() {
        assertEquals(4096, AgentArgs.parse("cap=4096").captureCap);
        assertEquals(4096, AgentArgs.parse(" future=1 , cap = 4096 ").captureCap);
    }

    @Test
    void capIsClamped() {
        assertEquals(16384, AgentArgs.parse("cap=1000000").captureCap);
        assertEquals(64, AgentArgs.parse("cap=1").captureCap);
    }

    @Test
    void malformedIsIgnored() {
        assertEquals(16384, AgentArgs.parse("cap=lots").captureCap);
        assertEquals(16384, AgentArgs.parse("cap,=3,===").captureCap);
    }
}
