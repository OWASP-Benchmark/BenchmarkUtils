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
 * @author Juan Gama
 * @created 2017
 */
package org.owasp.benchmarkutils.tools;

import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import org.apache.commons.lang.time.StopWatch;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.util.EntityUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.owasp.benchmarkutils.helpers.Utils;
import org.owasp.benchmarkutils.score.BenchmarkScore;

@Mojo(name = "run-crawler", requiresProject = false, defaultPhase = LifecyclePhase.COMPILE)
public class BenchmarkCrawler extends AbstractMojo {

    @Parameter(property = "crawlerFile")
    String crawlerFileName;

    private File crawlerFile = null;

    BenchmarkCrawler() {
        // Default constructor required for to support Maven plugin API.
        // The BenchmarkCrawler(File) must eventually be used before run() is invoked on that
        // instance of the Crawler.
    }

    BenchmarkCrawler(File file) {
        this.crawlerFile = file;
    }

    /** Crawl the target test suite. */
    protected void run() {
        try {
            List<AbstractTestCaseRequest> requests = Utils.parseHttpFile(crawlerFile);
            Collections.sort(
                    requests,
                    AbstractTestCaseRequest.getNameComparator()); // Probably not necessary
            crawl(requests);
        } catch (Exception e) {
            System.out.println("ERROR: Problem with specified crawler file: " + crawlerFile);
            e.printStackTrace();
            System.exit(-1);
        }
    }

    protected void crawl(List<AbstractTestCaseRequest> requests) throws Exception {
        CloseableHttpClient httpclient = createAcceptSelfSignedCertificateClient();
        long start = System.currentTimeMillis();

        for (AbstractTestCaseRequest request : requests) {

            // Send the next test case request
            try {
                sendRequest(httpclient, request);
            } catch (Exception e) {
                System.err.println("\n  FAILED: " + e.getMessage());
                e.printStackTrace();
            }
        }

        // Log the elapsed time for all test cases
        long stop = System.currentTimeMillis();
        int seconds = (int) (stop - start) / 1000;

        Date now = new Date();

        System.out.printf(
                "Crawl ran on %tF %<tT for %s v%s took %d seconds%n",
                now, BenchmarkScore.TESTSUITE, BenchmarkScore.TESTSUITEVERSION, seconds);
    }

    // This method taken directly from:
    // https://memorynotfound.com/ignore-certificate-errors-apache-httpclient/
    static CloseableHttpClient createAcceptSelfSignedCertificateClient()
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

    /**
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code.
     *
     * @param httpclient - The HTTP client to use to make the request
     * @param request - THe HTTP request to issue
     * @throws IOException
     */
    static ResponseInfo sendRequest(
            CloseableHttpClient httpclient, AbstractTestCaseRequest requestTC) {
        ResponseInfo responseInfo = new ResponseInfo();
        HttpUriRequest request = requestTC.buildRequest();
        responseInfo.setRequestBase(request);
        CloseableHttpResponse response = null;

        boolean isPost = request instanceof HttpPost;
        System.out.println((isPost ? "POST " : "GET ") + request.getURI());
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
            int statusCode = response.getStatusLine().getStatusCode();
            responseInfo.setStatusCode(statusCode);
            int seconds = (int) watch.getTime() / 1000;
            responseInfo.setTimeInSeconds(seconds);
            System.out.printf("--> (%d : %d sec)%n", statusCode, seconds);

            try {
                responseInfo.setResponseString(EntityUtils.toString(entity));
                EntityUtils.consume(entity);
            } catch (IOException e) {
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
     * Process the command line arguments that make any configuration changes.
     *
     * @param args - args passed to main().
     * @return specified crawler file if valid command line arguments provided. Null otherwise.
     */
    private static File processCommandLineArgs(String[] args) {

        // Set default location
        String crawlerFileName = new File(Utils.DATA_DIR, "benchmark-crawler-http.xml").getPath();
        File crawlerFile = new File(crawlerFileName); // default location;

        if (args == null || args.length == 0) {
            // No arguments is OK
        } else if (args.length != 0 && args.length != 2) {
            System.out.println("Usage: no arguments or -f /PATH/TO/TESTSUITE-crawler-http.xml");
            return null;
        } else if (args.length == 2) {
            if ("-f".equalsIgnoreCase(args[0])) {
                // -f indicates use the specified crawler file
                crawlerFileName = args[1];
                crawlerFile = new File(crawlerFileName);
            } else if (!(args[0] == null
                    && args[1] == null)) { // pom settings for crawler forces creation of 2 args,
                System.out.println("Supported options: -f /PATH/TO/TESTSUITE-crawler-http.xml");
                return null;
            }
        }
        if (!crawlerFile.exists()) {
            System.out.println(
                    "ERROR: Crawler Configuration file: '"
                            + crawlerFile.getAbsolutePath()
                            + "' not found!");
            crawlerFile = null;
        }

        return crawlerFile;
    }

    public void execute() throws MojoExecutionException, MojoFailureException {
        if (null == crawlerFileName) {
            System.out.println("ERROR: A crawler file must be specified.");
        } else {
            String[] mainArgs = {"-f", crawlerFileName};
            main(mainArgs);
        }
    }

    public static void main(String[] args) {

        File crawlerFile = processCommandLineArgs(args);
        if (crawlerFile == null) {
            return;
        }
        BenchmarkCrawler crawler = new BenchmarkCrawler(crawlerFile);
        crawler.run();
    }
}
