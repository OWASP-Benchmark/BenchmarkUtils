package org.owasp.benchmarkutils.entities;

public class CliResponseInfo implements ResponseInfo {
    private int seconds;
    private String responseString;
    private int returnCode;
    private CliRequest request;

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

    public int getReturnCode() {
        return returnCode;
    }

    public void setReturnCode(int returnCode) {
        this.returnCode = returnCode;
    }

    public CliRequest getRequest() {
        return request;
    }

    public void setRequest(CliRequest request) {
        this.request = request;
    }
}
