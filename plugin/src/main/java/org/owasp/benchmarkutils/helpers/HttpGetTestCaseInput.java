package org.owasp.benchmarkutils.helpers;

import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;

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
}
