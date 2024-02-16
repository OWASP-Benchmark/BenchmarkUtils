package org.owasp.benchmarkutils.entities;

import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("Jersey")
// @XmlType(name = "HttpPostTestCaseInput")
public class JerseyTestCaseInput extends HttpTestCaseInput {

    @Override
    void buildQueryString() {
        setQueryString("");
    }

    @Override
    void buildHeaders(HttpUriRequestBase request) {
        request.addHeader("Content-Type", "application/xml; charset=utf-8");
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
            // System.out.println("Cookie:" + name + "=" + value);
            request.addHeader("Cookie", name + "=" + value);
        }
    }

    @Override
    void buildBodyParameters(HttpUriRequestBase request) {
        String params = "<person>";
        for (RequestVariable field : getFormParameters()) {
            String name = field.getName();
            String value = field.getValue();
            params += "<" + name + ">" + escapeXML(value) + "</" + name + ">";
        }
        params += "</person>";
        StringEntity paramsEnt = new StringEntity(params);
        request.setEntity(paramsEnt);
    }

    private static String escapeXML(String value) {
        value = value.replace("&", "&amp;");
        value = value.replace("\"", "&quot;");
        value = value.replace("'", "&apos;");
        value = value.replace("<", "&lt;");
        value = value.replace(">", "&gt;");

        return value;
    }

    @Override
    HttpUriRequestBase createRequestInstance(String url) {
        // Apparently all Jersey Requests are POSTS. Never any query string params per buildQuery()
        // above.
        HttpPost httpPost = new HttpPost(url);
        return httpPost;
    }
}
