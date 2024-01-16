package org.owasp.benchmarkutils.helpers;

import org.apache.http.client.methods.HttpRequestBase;

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

    void buildBodyParameters(HttpRequestBase request) {
        // No request body
    }
}
