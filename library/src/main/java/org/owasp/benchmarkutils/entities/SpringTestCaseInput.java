package org.owasp.benchmarkutils.entities;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("Spring")
// @XmlType(name = "HttpPostTestCaseInput")
public class SpringTestCaseInput extends HttpTestCaseInput {

    @Override
    void buildQueryString() {
        setQueryString("");
    }

    @Override
    void buildHeaders(HttpUriRequestBase request) {
        request.addHeader("Content-type", "application/json"); // Should this add ;charset=utf-8?
        // No: "Designating the encoding is somewhat redundant for JSON, since the default encoding
        // for JSON is UTF-8."
        for (RequestVariable header : getHeaders()) {
            String name = header.getName();
            String value = header.getValue();
            System.out.println("Header:" + name + "=" + value);
            request.addHeader(name, value);
        }
    }

    @Override
    void buildCookies(HttpUriRequestBase request) {
        for (RequestVariable cookie : getCookies()) {
            String name = cookie.getName();
            String value = cookie.getValue();
            // System.out.println("Cookie:" + name + "=" + value);
            request.addHeader("Cookie", name + "=" + value);
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
        request.setEntity(paramsEnt);
    }

    @Override
    HttpUriRequestBase createRequestInstance(String url) {
        // Apparently all Spring Requests are POSTS. Never any query string params per buildQuery()
        // above.
        HttpPost httpPost = new HttpPost(url);
        return httpPost;
    }
}
