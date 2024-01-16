package org.owasp.benchmarkutils.helpers;

public class TestCaseSetupException extends Exception {

    public TestCaseSetupException(String message, Exception e) {
        super(message, e);
    }
}
