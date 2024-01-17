package org.owasp.benchmarkutils.helpers;

import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;

import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustAllStrategy;
//import org.apache.http.conn.ssl.NoopHostnameVerifier;
//import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
//import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
//import org.apache.http.impl.client.CloseableHttpClient;
//import org.apache.http.impl.client.HttpClients;
//import org.apache.http.ssl.SSLContextBuilder;
import org.apache.hc.core5.ssl.SSLContextBuilder;

public class HttpClientConfig extends TestCaseSetup {

    private static CloseableHttpClient httpclient;

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
        		PoolingHttpClientConnectionManagerBuilder.create().setSSLSocketFactory(connectionFactory).build();
        
        // finally create the HttpClient using HttpClient factory methods and assign the SSL Socket
        // Factory
        return HttpClients.custom().setConnectionManager(connectionManager).build();
    }

    public void setup() throws TestCaseSetupException {
        if (httpclient == null) {
            try {
                httpclient = createAcceptSelfSignedCertificateClient();
            } catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e) {
                throw new TestCaseSetupException(
                        "Could not setup HttpClientConfig for test case", e);
            }
        }
    }
}
