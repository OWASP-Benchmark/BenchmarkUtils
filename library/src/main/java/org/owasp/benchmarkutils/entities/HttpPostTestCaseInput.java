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
