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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Juan Gama
 * @created 2017
 */
package org.owasp.benchmarkutils.tools;

import java.io.UnsupportedEncodingException;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;
import org.owasp.benchmarkutils.helpers.RequestVariable;

@XmlDiscriminatorValue("SPRINGWS")
public class SpringTestCaseRequest extends AbstractTestCaseRequest {

    public SpringTestCaseRequest() {}

    @Override
    void buildQueryString() {
        setQuery("");
    }

    @Override
    HttpRequestBase createRequestInstance(String URL) {
        // Apparently all Spring Requests are POSTS. Never any query string params per buildQuery()
        // above.
        HttpPost httpPost = new HttpPost(URL);
        return httpPost;
    }

    @Override
    void buildHeaders(HttpRequestBase request) {
        request.addHeader("Content-type", "application/json");
        for (RequestVariable header : getHeaders()) {
            String name = header.getName();
            String value = header.getValue();
            System.out.println("Header:" + name + "=" + value);
            request.addHeader(name, value);
        }
    }

    @Override
    void buildCookies(HttpRequestBase request) {
        for (RequestVariable cookie : getCookies()) {
            String name = cookie.getName();
            String value = cookie.getValue();
            // System.out.println("Cookie:" + name + "=" + value);
            request.addHeader("Cookie", name + "=" + value);
        }
    }

    @Override
    void buildBodyParameters(HttpRequestBase request) {
        boolean first = true;
        String params = "{";
        for (RequestVariable field : getFormParams()) {
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
        try {
            StringEntity paramsEnt = new StringEntity(params);
            ((HttpEntityEnclosingRequestBase) request).setEntity(paramsEnt);
        } catch (UnsupportedEncodingException e) {
            System.out.println("Error encoding URL: " + e.getMessage());
        }
    }
}
