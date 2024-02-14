package org.owasp.benchmarkutils.entities;

import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("HttpGet")
// @XmlType(name = "HttpGetTestCaseInput")
public class HttpGetTestCaseInput extends HttpTestCaseInput {
    void buildQueryString() {
        setQueryString("");
        boolean first = true;
        for (RequestVariable field : getGetParameters()) {
            if (first) {
                setQueryString("?");
                first = false;
            } else {
                setQueryString(getQueryString() + "&");
            }
            String name = field.getName();
            String value = field.getValue();
            // System.out.println(query);
            setQueryString(getQueryString() + (name + "=" + urlEncode(value)));
        }
    }

    void buildBodyParameters(HttpUriRequestBase request) {
        // No request body
    }

    @Override
    HttpUriRequestBase createRequestInstance(String url) {
        HttpGet httpGet = new HttpGet(url);
        return httpGet;
    }
}
