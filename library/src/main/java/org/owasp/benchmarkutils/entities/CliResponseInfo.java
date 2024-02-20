package org.owasp.benchmarkutils.entities;

public class CliResponseInfo implements ResponseInfo {
    private int seconds;
    private String output;
    private int returnCode;
    private CliRequest request;

    public String getOutput() {
        return output;
    }

    public void setOutput(String output) {
        this.output = output;
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
