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
package org.owasp.benchmarkutils.tools;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;

@XmlRootElement(name = "HttpRequest")
public class HttpExecutor extends TestExecutor {
    HttpUriRequest httpRequest;

    public HttpExecutor() {}

    public HttpExecutor(HttpUriRequest httpRequest) {
        super();
        this.httpRequest = httpRequest;
    }

    public HttpUriRequest getHttpRequest() {
        return httpRequest;
    }

    public void setHttpRequest(HttpUriRequest httpRequest) {
        this.httpRequest = httpRequest;
    }

    public String getExecutorDescription() {
        StringWriter stringWriter = new StringWriter();
        PrintWriter out = new PrintWriter(stringWriter);

        out.println(httpRequest.toString());
        for (Header header : httpRequest.getHeaders()) {
            out.printf("%s:%s%n", header.getName(), header.getValue());
        }
        if (httpRequest instanceof HttpPost) {
            HttpPost postHttpRequest = (HttpPost) httpRequest;
            try {
                HttpEntity entity = postHttpRequest.getEntity();
                if (entity != null) {
                    out.print(IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8));
                }
            } catch (IOException e) {
                System.out.println("ERROR: Could not parse HttpPost entities");
                e.printStackTrace();
            }
        }
        out.flush();
        return stringWriter.toString();
    }
}
