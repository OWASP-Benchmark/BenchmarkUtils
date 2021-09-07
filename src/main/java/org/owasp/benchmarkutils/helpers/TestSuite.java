package org.owasp.benchmarkutils.helpers;

import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.owasp.benchmarkutils.tools.AbstractTestCaseRequest;

@XmlRootElement(name = "benchmarkSuite")
public class TestSuite {
    private List<AbstractTestCaseRequest> testCases;

    @XmlElement(name = "benchmarkTest")
    public List<AbstractTestCaseRequest> getTestCases() {
        return testCases;
    }

    public void setTestCases(List<AbstractTestCaseRequest> testCases) {
        this.testCases = testCases;
    }

    @Override
    public String toString() {
        return "TestSuite [testCases=" + testCases + "]";
    }
}
