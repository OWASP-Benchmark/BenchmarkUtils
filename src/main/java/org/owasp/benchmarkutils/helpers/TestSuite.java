package org.owasp.benchmarkutils.helpers;

import java.util.List;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.owasp.benchmarkutils.tools.AbstractTestCaseRequest;

@XmlRootElement(name = "benchmarkSuite")
public class TestSuite {
    private List<AbstractTestCaseRequest> testCases;

    private String name;

    private String version;

    @XmlElement(name = "benchmarkTest")
    public List<AbstractTestCaseRequest> getTestCases() {
        return testCases;
    }

    public void setTestCases(List<AbstractTestCaseRequest> testCases) {
        this.testCases = testCases;
    }

    @XmlAttribute(name = "testsuite", required = true)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @XmlAttribute(name = "version", required = true)
    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    @Override
    public String toString() {
        return "TestSuite [testCases=" + testCases + "]";
    }
}
