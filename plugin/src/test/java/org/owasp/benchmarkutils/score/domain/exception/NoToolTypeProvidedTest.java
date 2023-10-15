package org.owasp.benchmarkutils.score.domain.exception;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

public class NoToolTypeProvidedTest {

    @Test
    void hasCorrectMessage() {
        assertEquals("Mandatory tool type missing.", new NoToolTypeProvided().getMessage());
    }
}
