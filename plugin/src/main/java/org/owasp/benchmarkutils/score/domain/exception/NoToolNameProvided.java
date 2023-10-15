package org.owasp.benchmarkutils.score.domain.exception;

public class NoToolNameProvided extends RuntimeException {

    public NoToolNameProvided() {
        super("Mandatory tool name missing.");
    }
}
