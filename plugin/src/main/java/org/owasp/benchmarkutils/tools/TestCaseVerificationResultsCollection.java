package org.owasp.benchmarkutils.tools;

import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement(name = "TestCaseVerificationResultsCollection")
public class TestCaseVerificationResultsCollection {

    private List<TestCaseVerificationResults> resultsObjects;

    @XmlElement
    public List<TestCaseVerificationResults> getResultsObjects() {
        return resultsObjects;
    }

    public void setResultsObjects(List<TestCaseVerificationResults> resultsObjects) {
        this.resultsObjects = resultsObjects;
    }
}
