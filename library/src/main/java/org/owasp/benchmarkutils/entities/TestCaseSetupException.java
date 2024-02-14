package org.owasp.benchmarkutils.entities;

public class TestCaseSetupException extends Exception {

    public TestCaseSetupException(String message, Exception e) {
        super(message, e);
    }
}
