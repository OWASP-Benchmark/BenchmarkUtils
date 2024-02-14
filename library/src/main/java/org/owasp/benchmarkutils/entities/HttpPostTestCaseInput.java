package org.owasp.benchmarkutils.entities;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicClassicHttpRequest;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("HttpPost")
// @XmlType(name = "HttpPostTestCaseInput")
public class HttpPostTestCaseInput extends HttpTestCaseInput {
    @Override
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

    @Override
    void buildBodyParameters(HttpUriRequestBase request) {
        boolean first = true;
        String params = "{";
        for (RequestVariable field : getFormParameters()) {
            String name = field.getName();
            String value = field.getValue();
            // System.out.println(name+"="+value);
            if (first) {
                first = false;
            } else {
                params = params + ",";
            }
            params = params + String.format("\"%s\":\"%s\"", name, value.replace("\"", "\\\""));
        }
        params += "}";
        StringEntity paramsEnt = new StringEntity(params);
        ((BasicClassicHttpRequest) request).setEntity(paramsEnt);
    }

    @Override
    HttpUriRequestBase createRequestInstance(String url) {
        HttpPost httpPost = new HttpPost(url);
        return httpPost;
    }
}
