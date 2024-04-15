package org.owasp.benchmarkutils.entities;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "testcaseresult")
public class TestCaseResult {

    private String output;

    private boolean isPassed;

    public TestCaseResult(boolean isPassed, String output) {
        this.isPassed = isPassed;
        this.output = output;
    }

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
    }

    public boolean isPassed() {
        return isPassed;
    }

    public void setPassed(boolean isPassed) {
        this.isPassed = isPassed;
    }
}
