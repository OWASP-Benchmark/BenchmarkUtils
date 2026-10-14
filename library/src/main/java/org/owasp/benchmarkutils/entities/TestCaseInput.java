/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author David Anderson
 * @created 2024
 */
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
    TcpSocketExecutableTestCaseInput.class
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
