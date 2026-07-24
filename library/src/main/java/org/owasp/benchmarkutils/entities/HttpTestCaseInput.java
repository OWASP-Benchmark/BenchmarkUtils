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

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.validation.constraints.NotNull;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import org.apache.commons.lang.time.StopWatch;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.ssl.SSLContextBuilder;

public abstract class HttpTestCaseInput extends TestCaseInput {

    private String url;

    protected ContentFormatEnum contentFormat;

    private String queryString;

    private List<RequestVariable> formParameters;

    private List<RequestVariable> getParameters;

    private List<RequestVariable> cookies;

    private List<RequestVariable> headers;

    // private static CloseableHttpClient httpClient;

    void beforeMarshal(Marshaller marshaller) {
        //        System.out.println("Before marshal");
        if (formParameters != null && formParameters.isEmpty()) formParameters = null;
        if (getParameters != null && getParameters.isEmpty()) getParameters = null;
        if (cookies != null && cookies.isEmpty()) cookies = null;
        if (headers != null && headers.isEmpty()) headers = null;
    }

    void afterUnmarshal(Unmarshaller unmarshaller, Object parent) {
        //        System.out.println("After unmarshal");
        if (formParameters == null) formParameters = new ArrayList<RequestVariable>();
        if (getParameters == null) getParameters = new ArrayList<RequestVariable>();
        if (cookies == null) cookies = new ArrayList<RequestVariable>();
        if (headers == null) headers = new ArrayList<RequestVariable>();
    }

    @XmlElement(name = "url", required = true)
    @NotNull
    public String getUrl() {
        return url;
    }

    public String getQueryString() {
        return queryString;
    }

    @XmlElementWrapper(name = "formParams", required = false)
    @XmlElement(name = "formParam", required = false)
    @NotNull
    public List<RequestVariable> getFormParameters() {
        return formParameters;
    }

    @XmlElementWrapper(name = "getParams", required = false)
    @XmlElement(name = "getParam", required = false)
    @NotNull
    public List<RequestVariable> getGetParameters() {
        return getParameters;
    }

    @XmlElementWrapper(name = "cookies", required = false)
    @XmlElement(name = "cookie", required = false)
    @NotNull
    public List<RequestVariable> getCookies() {
        return cookies;
    }

    @XmlElementWrapper(name = "headers", required = false)
    @XmlElement(name = "header", required = false)
    @NotNull
    public List<RequestVariable> getHeaders() {
        return headers;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public void setQueryString(String queryString) {
        this.queryString = queryString;
    }

    public void setFormParameters(List<RequestVariable> formParameters) {
        this.formParameters = formParameters;
    }

    public void setGetParameters(List<RequestVariable> getParameters) {
        this.getParameters = getParameters;
    }

    public void setCookies(List<RequestVariable> cookies) {
        this.cookies = cookies;
    }

    public void setHeaders(List<RequestVariable> headers) {
        this.headers = headers;
    }

    public void addFormParameter(RequestVariable formParameter) {
        if (this.formParameters == null) {
            this.formParameters = new ArrayList<>();
        }
        this.formParameters.add(formParameter);
    }

    public void addGetParameter(RequestVariable getParameter) {
        if (this.getParameters == null) {
            this.getParameters = new ArrayList<>();
        }
        this.getParameters.add(getParameter);
    }

    public void addCookie(RequestVariable cookie) {
        if (this.cookies == null) {
            this.cookies = new ArrayList<>();
        }
        this.cookies.add(cookie);
    }

    public void addHeader(RequestVariable header) {
        if (this.headers == null) {
            this.headers = new ArrayList<>();
        }
        this.headers.add(header);
    }

    @XmlElement
    public ContentFormatEnum getContentFormat() {
        return contentFormat;
    }

    public void setContentFormat(ContentFormatEnum contentFormat) {
        this.contentFormat = contentFormat;
    }

    /** Defines what parameters in the body will be sent. */
    abstract void buildBodyParameters(HttpUriRequestBase request);

    /** Defines what cookies will be sent. */
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

    /** Defines what headers will be sent. */
    void buildHeaders(HttpUriRequestBase request) {
        for (RequestVariable header : getHeaders()) {
            String name = header.getName();
            String value = header.getValue();
            // System.out.println("Header:" + name + "=" + value);
            request.addHeader(name, value);
        }
    }

    @SuppressWarnings("deprecation")
    String urlEncode(String input) {
        return URLEncoder.encode(input);
    }

    /** Defines how to construct URL query string. */
    abstract void buildQueryString();

    //    public void execute() {
    //        // TODO: Not thread-safe
    //        // TODO: We never close this resource, which is poor form
    //        // TODO: What about other setup tasks, like starting a DB server or app server?
    //        if (httpclient == null) {
    //            httpclient = createAcceptSelfSignedCertificateClient();
    //        }
    //
    //        HttpUriRequestBase request = buildAttackRequest();
    //
    //        // Send the next test case request
    //        sendRequest(httpclient, request);
    //    }

    /**
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code.
     *
     * @param httpclient - The HTTP client to use to make the request
     * @param request - The HTTP request to issue
     */
    static ResponseInfo sendRequest(CloseableHttpClient httpclient, HttpUriRequest request) {
        // The default is this is a normal, non-attack request, so send false as isAttack value
        return sendRequest(httpclient, request, false);
    }

    /**
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code.
     *
     * @param httpclient - The HTTP client to use to make the request
     * @param request - The HTTP request to issue
     * @param attackRequest - Is the request an attack, or not
     */
    static ResponseInfo sendRequest(
            CloseableHttpClient httpclient, HttpUriRequest request, boolean attackRequest) {
        HttpResponseInfo responseInfo = new HttpResponseInfo(attackRequest);
        //      responseInfo.setRequestBase(request);
        responseInfo.setMethod(request.getMethod());
        URI uri = null;
        try {
            uri = request.getUri();
        } catch (URISyntaxException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        responseInfo.setUri(uri.toString());

        CloseableHttpResponse response = null;

        boolean isPost = request instanceof HttpPost;
        System.out.println((isPost ? "POST " : "GET ") + uri);

        StopWatch watch = new StopWatch();

        watch.start();
        try {
            response = httpclient.execute(request);
        } catch (IOException e) {
            e.printStackTrace();
        }
        watch.stop();

        try {
            HttpEntity entity = response.getEntity();
            int statusCode = response.getCode();
            responseInfo.setStatusCode(statusCode);
            int seconds = (int) watch.getTime() / 1000;
            responseInfo.setTimeInSeconds(seconds);
            System.out.printf("--> (%d : %d sec)%n", statusCode, seconds);

            try {
                responseInfo.setResponseString(EntityUtils.toString(entity));
                EntityUtils.consume(entity);
            } catch (IOException | org.apache.hc.core5.http.ParseException e) {
                e.printStackTrace();
            }
        } finally {
            if (response != null)
                try {
                    response.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
        return responseInfo;
    }

    /**
     * TODO: Make this class a POJO TestCase and pass it as an arg to another class TestCaseRequest
     * that can build an actual HttpUriRequest.
     *
     * @return
     */
    public HttpUriRequestBase buildRequest() {
        buildQueryString();
        HttpUriRequestBase request = createRequestInstance(getUrl() + getQueryString());
        buildHeaders(request);
        buildCookies(request);
        buildBodyParameters(request);
        return request;
    }

    abstract HttpUriRequestBase createRequestInstance(String url);

    public HttpUriRequestBase buildAttackRequest() {
        setSafe(false);
        return buildRequest();
    }

    public HttpUriRequestBase buildSafeRequest() {
        setSafe(true);
        return buildRequest();
    }

    public void setSafe(boolean isSafe) {
        //        this.isSafe = isSafe;
        for (RequestVariable header : getHeaders()) {
            // setSafe() considers whether attack and safe values exist for this parameter before
            // setting isSafe true or false. So you don't have to check that here.
            header.setSafe(isSafe);
        }
        for (RequestVariable cookie : getCookies()) {
            cookie.setSafe(isSafe);
        }
        for (RequestVariable getParam : getGetParameters()) {
            getParam.setSafe(isSafe);
        }
        for (RequestVariable formParam : getFormParameters()) {
            formParam.setSafe(isSafe);
        }
    }

    // This method taken directly from:
    // https://memorynotfound.com/ignore-certificate-errors-apache-httpclient/
    private CloseableHttpClient createAcceptSelfSignedCertificateClient()
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

        // use the TrustSelfSignedStrategy to allow Self Signed Certificates
        SSLContext sslContext =
                SSLContextBuilder.create()
                        .loadTrustMaterial(null, TrustAllStrategy.INSTANCE)
                        .build();

        // we can optionally disable hostname verification.
        // if you don't want to further weaken the security, you don't have to include this.
        HostnameVerifier allowAllHosts = new NoopHostnameVerifier();

        // create an SSL Socket Factory to use the SSLContext with the trust self signed certificate
        // strategy and allow all hosts verifier.
        SSLConnectionSocketFactory connectionFactory =
                new SSLConnectionSocketFactory(sslContext, allowAllHosts);
        HttpClientConnectionManager connectionManager =
                PoolingHttpClientConnectionManagerBuilder.create()
                        .setSSLSocketFactory(connectionFactory)
                        .build();

        // finally create the HttpClient using HttpClient factory methods and assign the SSL Socket
        // Factory
        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName()
                + " [url="
                + url
                + ", formParameters="
                + formParameters
                + ", getParameters="
                + getParameters
                + ", cookies="
                + cookies
                + ", headers="
                + headers
                + "]";
    }
}
