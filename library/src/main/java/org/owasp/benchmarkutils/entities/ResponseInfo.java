package org.owasp.benchmarkutils.entities;

public interface ResponseInfo {
    public String getResponseString();

    public void setResponseString(String responseString);

    public int getTimeInSeconds();

    public void setTimeInSeconds(int seconds);
}
