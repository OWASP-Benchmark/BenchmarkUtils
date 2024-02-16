package org.owasp.benchmarkutils.entities;

import javax.xml.bind.annotation.XmlSeeAlso;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorNode;

@XmlSeeAlso({
    CliArgExecutableTestCaseInput.class,
    CliFileExecutableTestCaseInput.class,
    ExecutableTestCaseInput.class,
    HttpTestCaseInput.class,
    JerseyTestCaseInput.class,
    ServletTestCaseInput.class,
    SpringTestCaseInput.class,
    StdinExecutableTestCaseInput.class,
    TcpSocketTestCaseInput.class
})
@XmlDiscriminatorNode("@type")
public abstract class TestCaseInput {

    public enum TestCaseInputType {
        HttpGet,
        HttpPost,
        CliArg
    }

    private String testCaseName;

    //    private TestCaseInputType type;

    abstract void setSafe(boolean isSafe);

    public String getTestCaseName() {
        return testCaseName;
    }

    public void setTestCaseName(String testCaseName) {
        this.testCaseName = testCaseName;
    }

    //    @XmlAttribute(name = "inputType", required = true)
    //    @XmlReadOnly
    //    @NotNull
    //    public TestCaseInputType getType() {
    //        return type;
    //    }
    //
    //    public void setType(TestCaseInputType type) {
    //        this.type = type;
    //    }

    //    abstract HttpUriRequestBase buildAttackRequest();
    //
    //    abstract HttpUriRequestBase buildSafeRequest();

    @Override
    public String toString() {
        return this.getClass().getSimpleName();
        // return this.getClass().getSimpleName() + " [" + "type=" + type + "]";
    }
}
