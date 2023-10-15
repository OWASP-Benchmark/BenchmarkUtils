package org.owasp.benchmarkutils.score.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class NoToolNameProvidedTest {

    @Test
    void hasCorrectMessage() {
        assertEquals("Mandatory tool name missing.", new NoToolNameProvided().getMessage());
    }
}
