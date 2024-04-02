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

import java.io.StringWriter;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlRootElement;
import org.eclipse.persistence.jaxb.MarshallerProperties;
import org.eclipse.persistence.oxm.MediaType;

@XmlRootElement(name = "ResponseInfo")
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

    public String toJSON() {
        try {
            JAXBContext jaxbContext =
                    org.eclipse.persistence.jaxb.JAXBContextFactory.createContext(
                            new Class[] {ResponseInfo.class}, null);

            Marshaller jaxbMarshaller = jaxbContext.createMarshaller();

            // Set JSON type
            jaxbMarshaller.setProperty(MarshallerProperties.MEDIA_TYPE, MediaType.APPLICATION_JSON);
            jaxbMarshaller.setProperty(MarshallerProperties.JSON_INCLUDE_ROOT, true);

            // To format JSON
            jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);

            // Print JSON String to Console
            StringWriter sw = new StringWriter();
            jaxbMarshaller.marshal(this, sw);
            return sw.toString();
        } catch (JAXBException e) {
            e.printStackTrace();
            return "";
        }
    }
}
