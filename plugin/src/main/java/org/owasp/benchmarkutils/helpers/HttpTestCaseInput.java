package org.owasp.benchmarkutils.helpers;

import java.net.URLEncoder;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;

public abstract class HttpTestCaseInput extends TestCaseInput {

    private String url;

    @XmlElement(required = true)
    protected ContentFormatEnum contentFormat;

    private String queryString;

    private List<RequestVariable> formParameters;

    private List<RequestVariable> getParameters;

    private List<RequestVariable> cookies;

    private List<RequestVariable> headers;

    private static CloseableHttpClient httpclient;

    @XmlAttribute(name = "URL", required = true)
    @NotNull
    public String getUrl() {
        return url;
    }

    public String getQueryString() {
        return queryString;
    }

    @XmlElement(name = "formparam")
    @NotNull
    public List<RequestVariable> getFormParameters() {
        return formParameters;
    }

    @XmlElement(name = "getparam")
    @NotNull
    public List<RequestVariable> getGetParameters() {
        return getParameters;
    }

    @XmlElement(name = "cookie")
    @NotNull
    public List<RequestVariable> getCookies() {
        return cookies;
    }

    @XmlElement(name = "header")
    @NotNull
    public List<RequestVariable> getHeaders() {
        return headers;
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

    public ContentFormatEnum getContentFormat() {
        return contentFormat;
    }

    public void setContentFormat(ContentFormatEnum contentFormat) {
        this.contentFormat = contentFormat;
    }

    /** Defines what parameters in the body will be sent. */
    abstract void buildBodyParameters(HttpRequestBase request);

    /** Defines what cookies will be sent. */
    void buildCookies(HttpRequestBase request) {
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
    void buildHeaders(HttpRequestBase request) {
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

    public void execute() {
        // TODO: Not thread-safe
        // TODO: We never close this resource, which is poor form
        // TODO: What about other setup tasks, like starting a DB server or app server?
        if (httpclient == null) {
            httpclient = createAcceptSelfSignedCertificateClient();
        }

        HttpUriRequest request = buildAttackRequest();

        // Send the next test case request
        sendRequest(httpclient, request);
    }

    /**
     * TODO: Make this class a POJO TestCase and pass it as an arg to another class TestCaseRequest
     * that can build an actual HttpUriRequest.
     *
     * @return
     */
    public HttpUriRequest buildRequest() {
        buildQueryString();
        HttpRequestBase request = createRequestInstance(fullURL + query);
        buildHeaders(request);
        buildCookies(request);
        buildBodyParameters(request);
        return request;
    }

    public HttpUriRequest buildAttackRequest() {
        setSafe(false);
        return buildRequest();
    }

    public HttpUriRequest buildSafeRequest() {
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
        for (RequestVariable getParam : getGetParams()) {
            getParam.setSafe(isSafe);
        }
        for (RequestVariable formParam : getFormParams()) {
            formParam.setSafe(isSafe);
        }
    }

    // This method taken directly from:
    // https://memorynotfound.com/ignore-certificate-errors-apache-httpclient/
    private CloseableHttpClient createAcceptSelfSignedCertificateClient()
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

        // use the TrustSelfSignedStrategy to allow Self Signed Certificates
        SSLContext sslContext =
                SSLContextBuilder.create().loadTrustMaterial(new TrustSelfSignedStrategy()).build();

        // we can optionally disable hostname verification.
        // if you don't want to further weaken the security, you don't have to include this.
        HostnameVerifier allowAllHosts = new NoopHostnameVerifier();

        // create an SSL Socket Factory to use the SSLContext with the trust self signed certificate
        // strategy and allow all hosts verifier.
        SSLConnectionSocketFactory connectionFactory =
                new SSLConnectionSocketFactory(sslContext, allowAllHosts);

        // finally create the HttpClient using HttpClient factory methods and assign the SSL Socket
        // Factory
        return HttpClients.custom().setSSLSocketFactory(connectionFactory).build();
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
