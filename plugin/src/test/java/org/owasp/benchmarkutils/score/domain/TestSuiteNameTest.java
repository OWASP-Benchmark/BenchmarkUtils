package org.owasp.benchmarkutils.score.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class TestSuiteNameTest {

    @Test
    void returnsSimpleName() {
        assertEquals("SimpleName", new TestSuiteName("SimpleName").simpleName());
        assertEquals("Benchmark", new TestSuiteName("Benchmark").simpleName());
    }

    @Test
    void returnsFixedFullNameForBenchmark() {
        assertEquals("OWASP Benchmark", new TestSuiteName("Benchmark").fullName());
    }

    @Test
    void returnsSimpleNameForFullNameWhenNotBenchmark() {
        assertEquals("SimpleName", new TestSuiteName("SimpleName").fullName());
    }
}
