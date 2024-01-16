package org.owasp.benchmarkutils.helpers;

import java.io.UnsupportedEncodingException;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;

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
    void buildBodyParameters(HttpRequestBase request) {
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
        try {
            StringEntity paramsEnt = new StringEntity(params);
            ((HttpEntityEnclosingRequestBase) request).setEntity(paramsEnt);
        } catch (UnsupportedEncodingException e) {
            System.out.println("Error encoding URL: " + e.getMessage());
        }
    }
}
