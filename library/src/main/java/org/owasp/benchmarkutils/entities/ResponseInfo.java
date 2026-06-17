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

import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorNode;

@XmlRootElement(name = "ResponseInfo")
@XmlSeeAlso({CliResponseInfo.class, HttpResponseInfo.class})
@XmlDiscriminatorNode("@type")
public abstract class ResponseInfo {

    // True if response to an attack request. False if response to normal request
    private boolean isAttackResponse = false; // Default
    private String responseString;
    private int statusCode;
    private int seconds;

    public ResponseInfo() {
        // Default is this is a normal, non-attack response
    }

    public ResponseInfo(boolean attackRequest) {
        this.isAttackResponse = attackRequest;
    }

    public void setIsAttackResponse(boolean isAttackResponse) {
        this.isAttackResponse = isAttackResponse;
    }

    @XmlAttribute(required = true)
    public boolean getIsAttackResponse() {
        return isAttackResponse;
    }

    public void setResponseString(String responseString) {
        this.responseString = responseString;
    }

    @XmlAttribute(required = true)
    public String getResponseString() {
        return responseString;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public int getTimeInSeconds() {
        return seconds;
    }

    public void setTimeInSeconds(int seconds) {
        this.seconds = seconds;
    }
}
