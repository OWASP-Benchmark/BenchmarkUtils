package org.owasp.benchmarkutils.tools;

/** Not a great class name. */
public class TestCaseVerificationResults {
    private AbstractTestCaseRequest request;

    private ResponseInfo responseToAttackValue;

    private ResponseInfo responseToSafeValue;

    private boolean isUnverifiable;

    private boolean isDeclaredUnverifiable;

    private boolean isPassed;

    public TestCaseVerificationResults(
            AbstractTestCaseRequest request,
            ResponseInfo responseToAttackValue,
            ResponseInfo responseToSafeValue) {
        this(request, responseToAttackValue, responseToSafeValue, true, false, false);
    }

    public TestCaseVerificationResults(
            AbstractTestCaseRequest request,
            ResponseInfo responseToAttackValue,
            ResponseInfo responseToSafeValue,
            boolean isUnverifiable,
            boolean isDeclaredVerifiable,
            boolean isPassed) {
        super();
        this.request = request;
        this.responseToAttackValue = responseToAttackValue;
        this.responseToSafeValue = responseToSafeValue;
        this.isUnverifiable = isUnverifiable;
        this.isDeclaredUnverifiable = isDeclaredVerifiable;
        this.isPassed = isPassed;
    }

    public AbstractTestCaseRequest getRequest() {
        return request;
    }

    public void setRequest(AbstractTestCaseRequest request) {
        this.request = request;
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
}
