package org.owasp.benchmarkutils.tools;

import org.apache.hc.client5.http.classic.methods.HttpUriRequest;

class ResponseInfo {
    private String responseString;
    private int seconds;
    private int statusCode;
    private HttpUriRequest requestBase;

    public String getResponseString() {
        return responseString;
    }

    public void setResponseString(String responseString) {
        this.responseString = responseString;
    }

    public int getTimeInSeconds() {
        return seconds;
    }

    public void setTimeInSeconds(int seconds) {
        this.seconds = seconds;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public HttpUriRequest getRequestBase() {
        return requestBase;
    }

    public void setRequestBase(HttpUriRequest request) {
        this.requestBase = request;
    }
}
