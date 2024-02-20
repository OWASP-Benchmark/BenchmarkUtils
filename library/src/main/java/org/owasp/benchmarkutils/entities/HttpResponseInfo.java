package org.owasp.benchmarkutils.entities;

import org.apache.hc.client5.http.classic.methods.HttpUriRequest;

public class HttpResponseInfo implements ResponseInfo {
    private String responseString;
    private int seconds;
    private int statusCode;
    private HttpUriRequest requestBase;

    @Override
    public String getResponseString() {
        return responseString;
    }

    @Override
    public void setResponseString(String responseString) {
        this.responseString = responseString;
    }

    @Override
    public int getTimeInSeconds() {
        return seconds;
    }

    @Override
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
