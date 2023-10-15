package org.owasp.benchmarkutils.score.domain.exception;

public class NoToolTypeProvided extends RuntimeException {

    public NoToolTypeProvided() {
        super("Mandatory tool type missing.");
    }
}
