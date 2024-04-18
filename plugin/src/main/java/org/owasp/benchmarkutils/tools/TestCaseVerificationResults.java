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
 * @created 2021
 */
package org.owasp.benchmarkutils.tools;

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.owasp.benchmarkutils.entities.ResponseInfo;
import org.owasp.benchmarkutils.entities.TestCase;

/** Not a great class name. */
@XmlRootElement(name = "TestCaseVerificationResult")
public class TestCaseVerificationResults {

    private ResponseInfo responseToAttackValue;

    private ResponseInfo responseToSafeValue;

    private boolean isUnverifiable;

    private boolean isDeclaredUnverifiable;

    private boolean isPassed;

    private TestExecutor attackTestExecutor;

    private TestExecutor safeTestExecutor;

    private TestCase testCase;

    public TestCaseVerificationResults() {
        super();
    }

    public TestCaseVerificationResults(
            TestExecutor attackTestExecutor,
            TestExecutor safeTestExecutor,
            TestCase testCase,
            ResponseInfo responseToAttackValue,
            ResponseInfo responseToSafeValue) {
        this(
                attackTestExecutor,
                safeTestExecutor,
                testCase,
                responseToAttackValue,
                responseToSafeValue,
                true,
                false,
                false);
    }

    public TestCaseVerificationResults(
            TestExecutor attackTestExecutor,
            TestExecutor safeTestExecutor,
            TestCase testCase,
            ResponseInfo responseToAttackValue,
            ResponseInfo responseToSafeValue,
            boolean isUnverifiable,
            boolean isDeclaredVerifiable,
            boolean isPassed) {
        super();
        this.attackTestExecutor = attackTestExecutor;
        this.safeTestExecutor = safeTestExecutor;
        this.testCase = testCase;
        this.responseToAttackValue = responseToAttackValue;
        this.responseToSafeValue = responseToSafeValue;
        this.isUnverifiable = isUnverifiable;
        this.isDeclaredUnverifiable = isDeclaredVerifiable;
        this.isPassed = isPassed;
    }

    @XmlElement(name = "AttackResponseInfo")
    public ResponseInfo getResponseToAttackValue() {
        return responseToAttackValue;
    }

    public void setResponseToAttackValue(ResponseInfo responseToAttackValue) {
        this.responseToAttackValue = responseToAttackValue;
    }

    @XmlElement(name = "SafeResponseInfo", required = true)
    public ResponseInfo getResponseToSafeValue() {
        return responseToSafeValue;
    }

    public void setResponseToSafeValue(ResponseInfo responseToSafeValue) {
        this.responseToSafeValue = responseToSafeValue;
    }

    @XmlAttribute(name = "Unverifiable")
    public boolean isUnverifiable() {
        return isUnverifiable;
    }

    public void setUnverifiable(boolean isUnverifiable) {
        this.isUnverifiable = isUnverifiable;
    }

    @XmlAttribute(name = "DeclaredUnverifiable")
    public boolean isDeclaredUnverifiable() {
        return isDeclaredUnverifiable;
    }

    public void setDeclaredUnverifiable(boolean isDeclaredUnverifiable) {
        this.isDeclaredUnverifiable = isDeclaredUnverifiable;
    }

    @XmlAttribute(name = "Passed")
    public boolean isPassed() {
        return isPassed;
    }

    public void setPassed(boolean isPassed) {
        this.isPassed = isPassed;
    }

    @XmlElement(name = "AttackRequestInfo")
    public TestExecutor getAttackTestExecutor() {
        return attackTestExecutor;
    }

    public void setAttackTestExecutor(TestExecutor attackTestExecutor) {
        this.attackTestExecutor = attackTestExecutor;
    }

    @XmlElement(name = "SafeRequestInfo")
    public TestExecutor getSafeTestExecutor() {
        return safeTestExecutor;
    }

    public void setSafeTestExecutor(TestExecutor safeTestExecutor) {
        this.safeTestExecutor = safeTestExecutor;
    }

    @XmlElement(name = "TestCase")
    public TestCase getTestCase() {
        return testCase;
    }

    public void setTestCase(TestCase testCase) {
        this.testCase = testCase;
    }
}
