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

import java.util.ArrayList;
import java.util.List;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.core5.http.NameValuePair;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("Servlet")
public class ServletTestCaseInput extends HttpTestCaseInput {

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
    void buildHeaders(HttpUriRequestBase request) {
        // AJAX does: text/plain;charset=UTF-8, while HTML Form: application/x-www-form-urlencoded
        // request.addHeader("Content-Type", ";charset=UTF-8"); --This BREAKS BenchmarkCrawling
        request.addHeader(
                "Content-Type", "application/x-www-form-urlencoded"); // Works for both though

        for (RequestVariable header : getHeaders()) {
            String name = header.getName();
            String value = header.getValue();
            // System.out.println("Header:" + name + "=" + value);
            request.addHeader(name, value);
        }
    }

    @Override
    void buildCookies(HttpUriRequestBase request) {
        for (RequestVariable cookie : getCookies()) {
            String name = cookie.getName();
            String value = cookie.getValue();
            // Note: URL encoding of a space becomes a +, which is OK for Java, but
            // not other languages. So after URLEncoding, replace all + with %20, which is the
            // standard URL encoding for a space char.
            request.addHeader("Cookie", name + "=" + urlEncode(value).replace("+", "%20"));
        }
    }

    @Override
    void buildBodyParameters(HttpUriRequestBase request) {
        List<NameValuePair> fields = new ArrayList<>();
        for (RequestVariable formParam : getFormParameters()) {
            fields.add(formParam.getNameValuePair());
        }

        // Add the body parameters to the request if there were any
        if (fields.size() > 0) {
            request.setEntity(new UrlEncodedFormEntity(fields));
        }
    }

    @Override
    HttpUriRequestBase createRequestInstance(String url) {
        HttpUriRequestBase httpUriRequestBase;
        if (getQueryString().length() == 0) {
            httpUriRequestBase = new HttpPost(url);
        } else {
            httpUriRequestBase = new HttpGet(url);
        }
        return httpUriRequestBase;
    }
}
