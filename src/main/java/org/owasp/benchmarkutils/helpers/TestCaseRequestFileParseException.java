package org.owasp.benchmarkutils.helpers;

public class TestCaseRequestFileParseException extends Exception {

    public TestCaseRequestFileParseException(String message) {
        super(message);
    }

    public TestCaseRequestFileParseException(String message, Exception e) {
        super(message, e);
    }
}
