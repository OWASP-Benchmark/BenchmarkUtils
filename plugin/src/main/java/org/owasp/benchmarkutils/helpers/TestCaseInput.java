package org.owasp.benchmarkutils.helpers;

import javax.xml.bind.annotation.XmlSeeAlso;

@XmlSeeAlso({
    CliArgExecutableTestCaseInput.class,
    CliFileExecutableTestCaseInput.class,
    HttpTestCaseInput.class,
    StdinExecutableTestCaseInput.class,
    TCPSocketTestCaseInput.class
})
public abstract class TestCaseInput {

    private String testCaseName;

    abstract void execute(String testCaseName);

    abstract void setSafe(boolean isSafe);

    public String getTestCaseName() {
        return testCaseName;
    }

    public void setTestCaseName(String testCaseName) {
        this.testCaseName = testCaseName;
    }
}
