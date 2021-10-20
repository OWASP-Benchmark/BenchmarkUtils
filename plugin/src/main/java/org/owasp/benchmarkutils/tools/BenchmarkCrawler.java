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
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.time.StopWatch;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
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
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.TestSuite;
import org.owasp.benchmarkutils.helpers.Utils;
import org.owasp.benchmarkutils.score.BenchmarkScore;

@Mojo(name = "run-crawler", requiresProject = false, defaultPhase = LifecyclePhase.COMPILE)
public class BenchmarkCrawler extends AbstractMojo {

    public static String proxyHost, proxyPort;

    @Parameter(property = "crawlerFile")
    String pluginFilenameParam;

    /*
     * Attaching the @Parameter property to the crawlerFile variable directly didn't work for some
     * reason. So I attached it to a new String variable, and set it later. No clue why it doesn't
     * work. But for now, leaving it this way because it works.
     *
     * If you run the mvn command with -X, when invoking this plugin, you'd see something like
     * this at the end:
     *
     * [DEBUG] (s) crawlerFile = /Users/PATH/TO/BenchmarkJava/data/benchmark-crawler-http.xml
     * [DEBUG] -- end configuration --
     * but the crawlerFile variable would be null.
     *
     * When it should be:
     * [DEBUG] (f) crawlerFile = data/benchmark-crawler-http.xml
     * [DEBUG] -- end configuration --
     *
     * So after changing this, I now get:
     * [DEBUG] (f) pluginFilenameParam = data/benchmark-crawler-http.xml
     * [DEBUG] -- end configuration --
     * and the pluginFilenameParam variable value is set properly.
     */
    String crawlerFile;

    File theCrawlerFile;
    String selectedTestCaseName = null;
    TestSuite testSuite;

    BenchmarkCrawler() {
        // A default constructor required to support Maven plugin API.
        // The theCrawlerFile has to be instantiated before a crawl can be done.
    }

    /** Crawl the target test suite. */
    protected void run() {
        try {
            crawl(testSuite);
        } catch (Exception e) {
            System.out.println("ERROR: Problem crawling");
            e.printStackTrace();
        }
    }

    void load() {
        try {
            // Force initialization of the Categories singleton.
            InputStream categoriesFileStream =
                    BenchmarkScore.class.getClassLoader().getResourceAsStream(Categories.FILENAME);
            new Categories(categoriesFileStream);

            this.testSuite = Utils.parseHttpFile(this.theCrawlerFile);
            Collections.sort(
                    this.testSuite.getTestCases(),
                    AbstractTestCaseRequest.getNameComparator()); // Probably not necessary

            // This allows a single test case to be tested, rather than all of them.
            if (selectedTestCaseName != null) {
                for (AbstractTestCaseRequest request : this.testSuite.getTestCases()) {
                    if (request.getName().equals(selectedTestCaseName)) {
                        List<AbstractTestCaseRequest> requests = new ArrayList<>();
                        requests.add(request);
                        this.testSuite = new TestSuite();
                        this.testSuite.setTestCases(requests);
                        break;
                    }
                }
            }
        } catch (Exception e) {
            System.out.println(
                    "ERROR: Problem with specified crawler file: " + this.theCrawlerFile);
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public void setCrawlerFile(File theCrawlerFile) {
        this.theCrawlerFile = theCrawlerFile;
    }

    /**
     * This method could be static, but needs to be an instance method so Verification crawler can
     * overrite this method.
     *
     * @param testSuite The TestSuite to crawl.
     * @throws Exception
     */
    protected void crawl(TestSuite testSuite) throws Exception {
        CloseableHttpClient httpclient = createAcceptSelfSignedCertificateClient();
        long start = System.currentTimeMillis();

        for (AbstractTestCaseRequest requestTemplate : testSuite.getTestCases()) {

            HttpUriRequest request = requestTemplate.buildAttackRequest();

            // Send the next test case request
            sendRequest(httpclient, request);
        }

        // Log the elapsed time for all test cases
        long stop = System.currentTimeMillis();
        int seconds = (int) (stop - start) / 1000;

        Date now = new Date();

        System.out.printf(
                "Crawl ran on %tF %<tT for %s v%s took %d seconds%n",
                now, testSuite.getName(), testSuite.getVersion(), seconds);
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

        // Set Proxy settings
        HttpHost httpHost = null;
        if ((proxyHost = System.getProperty("proxyHost")) != null
                && (proxyPort = System.getProperty("proxyPort")) != null) {
            httpHost = new HttpHost(proxyHost, Integer.parseInt(proxyPort));
            // finally create the HttpClient using HttpClient factory methods and assign the SSL
            // Socket Factory and assign the setProxy
            return HttpClients.custom()
                    .setSSLSocketFactory(connectionFactory)
                    .setProxy(httpHost)
                    .build();
        } else {
            // finally create the HttpClient using HttpClient factory methods and assign the SSL
            // Socket Factory
            return HttpClients.custom().setSSLSocketFactory(connectionFactory).build();
        }
    }

    /**
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code.
     *
     * @param httpclient - The HTTP client to use to make the request
     * @param request - THe HTTP request to issue
     */
    static ResponseInfo sendRequest(CloseableHttpClient httpclient, HttpUriRequest request) {
        ResponseInfo responseInfo = new ResponseInfo();
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
    private void processCommandLineArgs(String[] args) {

        // Create the command line parser
        CommandLineParser parser = new DefaultParser();

        HelpFormatter formatter = new HelpFormatter();

        // Create the Options
        Options options = new Options();
        options.addOption(
                Option.builder("f")
                        .longOpt("file")
                        .desc("a TESTSUITE-crawler-http.xml file")
                        .hasArg()
                        .build());
        options.addOption(
                Option.builder("n")
                        .longOpt("name")
                        .desc("tescase name (e.g. BenchmarkTestCase00025)")
                        .hasArg()
                        .build());

        try {
            // Parse the command line arguments
            CommandLine line = parser.parse(options, args);

            if (line.hasOption("f")) {
                this.crawlerFile = line.getOptionValue("f");
                File targetFile = new File(this.crawlerFile);
                if (targetFile.exists()) {
                    setCrawlerFile(targetFile);
                } else {
                    throw new RuntimeException(
                            "Could not find crawler configuration file '" + this.crawlerFile + "'");
                }
            }
            if (line.hasOption("h")) {
                formatter.printHelp("BenchmarkCrawlerVerification", options, true);
            }
            if (line.hasOption("n")) {
                selectedTestCaseName = line.getOptionValue("n");
            }
        } catch (ParseException e) {
            formatter.printHelp("BenchmarkCrawler", options);
            throw new RuntimeException("Error parsing arguments: ", e);
        }
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (null == this.pluginFilenameParam) {
            System.out.println("ERROR: A crawlerFile parameter must be specified.");
        } else {
            String[] mainArgs = {"-f", this.pluginFilenameParam};
            main(mainArgs);
        }
    }

    public static void main(String[] args) {

        BenchmarkCrawler crawler = new BenchmarkCrawler();
        crawler.processCommandLineArgs(args);
        crawler.load();
        crawler.run();
    }
}
