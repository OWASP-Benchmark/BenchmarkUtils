package org.owasp.benchmarkutils.tools;

import org.apache.hc.client5.http.classic.methods.HttpUriRequest;

/** Not a great class name. */
public class TestCaseVerificationResults {

    private ResponseInfo responseToAttackValue;

    private ResponseInfo responseToSafeValue;

    private boolean isUnverifiable;

    private boolean isDeclaredUnverifiable;

    private boolean isPassed;

    private HttpUriRequest attackRequest;

    private HttpUriRequest safeRequest;

    private AbstractTestCaseRequest requestTemplate;

    public TestCaseVerificationResults(
            HttpUriRequest attackRequest,
            HttpUriRequest safeRequest,
            AbstractTestCaseRequest requestTemplate,
            ResponseInfo responseToAttackValue,
            ResponseInfo responseToSafeValue) {
        this(
                attackRequest,
                safeRequest,
                requestTemplate,
                responseToAttackValue,
                responseToSafeValue,
                true,
                false,
                false);
    }

    public TestCaseVerificationResults(
            HttpUriRequest attackRequest,
            HttpUriRequest safeRequest,
            AbstractTestCaseRequest requestTemplate,
            ResponseInfo responseToAttackValue,
            ResponseInfo responseToSafeValue,
            boolean isUnverifiable,
            boolean isDeclaredVerifiable,
            boolean isPassed) {
        super();
        this.attackRequest = attackRequest;
        this.safeRequest = safeRequest;
        this.requestTemplate = requestTemplate;
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

    public HttpUriRequest getAttackRequest() {
        return attackRequest;
    }

    public void setAttackRequest(HttpUriRequest attackRequest) {
        this.attackRequest = attackRequest;
    }

    public HttpUriRequest getSafeRequest() {
        return safeRequest;
    }

    public void setSafeRequest(HttpUriRequest safeRequest) {
        this.safeRequest = safeRequest;
    }

    public AbstractTestCaseRequest getRequestTemplate() {
        return requestTemplate;
    }

    public void setRequestTemplate(AbstractTestCaseRequest requestTemplate) {
        this.requestTemplate = requestTemplate;
    }
}
