package org.owasp.benchmarkutils.tools;

import org.owasp.benchmarkutils.entities.ResponseInfo;
import org.owasp.benchmarkutils.entities.TestCase;

/** Not a great class name. */
public class TestCaseVerificationResults {

    private ResponseInfo responseToAttackValue;

    private ResponseInfo responseToSafeValue;

    private boolean isUnverifiable;

    private boolean isDeclaredUnverifiable;

    private boolean isPassed;

    private TestExecutor attackTestExecutor;

    private TestExecutor safeTestExecutor;

    private TestCase testCase;

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

    public ResponseInfo getResponseToAttackValue() {
        return responseToAttackValue;
    }

    public void setResponseToAttackValue(ResponseInfo responseToAttackValue) {
        this.responseToAttackValue = responseToAttackValue;
    }

    public ResponseInfo getResponseToSafeValue() {
        return responseToSafeValue;
    }

    public void setResponseToSafeValue(ResponseInfo responseToSafeValue) {
        this.responseToSafeValue = responseToSafeValue;
    }

    public boolean isUnverifiable() {
        return isUnverifiable;
    }

    public void setUnverifiable(boolean isUnverifiable) {
        this.isUnverifiable = isUnverifiable;
    }

    public boolean isDeclaredUnverifiable() {
        return isDeclaredUnverifiable;
    }

    public void setDeclaredUnverifiable(boolean isDeclaredUnverifiable) {
        this.isDeclaredUnverifiable = isDeclaredUnverifiable;
    }

    public void setPassed(boolean isPassed) {
        this.isPassed = isPassed;
    }

    public boolean isPassed() {
        return isPassed;
    }

    public TestExecutor getAttackTestExecutor() {
        return attackTestExecutor;
    }

    public void setAttackTestExecutor(TestExecutor attackTestExecutor) {
        this.attackTestExecutor = attackTestExecutor;
    }

    public TestExecutor getSafeTestExecutor() {
        return safeTestExecutor;
    }

    public void setSafeTestExecutor(TestExecutor safeTestExecutor) {
        this.safeTestExecutor = safeTestExecutor;
    }

    public TestCase getTestCase() {
        return testCase;
    }

    public void setTestCase(TestCase testCase) {
        this.testCase = testCase;
    }
}
