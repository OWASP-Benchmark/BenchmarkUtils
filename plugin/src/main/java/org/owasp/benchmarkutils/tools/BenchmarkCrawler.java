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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.StringJoiner;
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
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
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
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.owasp.benchmarkutils.entities.CliRequest;
import org.owasp.benchmarkutils.entities.CliResponseInfo;
import org.owasp.benchmarkutils.entities.ExecutableTestCaseInput;
import org.owasp.benchmarkutils.entities.HttpResponseInfo;
import org.owasp.benchmarkutils.entities.HttpTestCaseInput;
import org.owasp.benchmarkutils.entities.RequestVariable;
import org.owasp.benchmarkutils.entities.ResponseInfo;
import org.owasp.benchmarkutils.entities.TestCase;
import org.owasp.benchmarkutils.entities.TestSuite;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.Utils;
import org.owasp.benchmarkutils.score.BenchmarkScore;

@Mojo(name = "run-crawler", requiresProject = false, defaultPhase = LifecyclePhase.COMPILE)
public class BenchmarkCrawler extends AbstractMojo {

    // Intended to be a Singleton. So when instantiated, put it here:
    static BenchmarkCrawler thisInstance = null;

    @Parameter(property = "crawlerFile")
    String pluginFilenameParam;

    @Parameter(property = "testCaseName")
    String pluginTestCaseNameParam;

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
            // System.out.println("Test suite: " + this.testSuite);
            Collections.sort(
                    this.testSuite.getTestCases(),
                    TestCase.getNameComparator()); // Probably not necessary

            // This allows a single test case to be tested, rather than all of them.
            if (selectedTestCaseName != null) {
                for (TestCase request : this.testSuite.getTestCases()) {
                    if (request.getName().equals(selectedTestCaseName)) {
                        List<TestCase> requests = new ArrayList<>();
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
     * override this method.
     *
     * @param testSuite The TestSuite to crawl.
     * @throws Exception
     */
    protected void crawl(TestSuite testSuite) throws Exception {
        // Use try-with-resources to close this resource before returning
        try (CloseableHttpClient httpClient = createAcceptSelfSignedCertificateClient()) {
            long start = System.currentTimeMillis();

            // Iterate through TestCase objects instead.
            // Execution of the test case depends on the type of TestCase.getTestCaseInput()
            // Where should the code that executes the test case go?
            // Maybe I need a TestCaseExecuter that takes a TestCaseInput to initialize.
            //      for (TestCase testCase : testSuite.getTestCases()) {
            //    	if (testCase.getTestCaseInput() instanceof HttpTestCaseInput) {
            //    		HttpUriRequest request =
            // testCase.getAttackTestCaseRequest().buildAttackRequest();
            //    		sendRequest(httpclient, request);
            //    	} else if (testCase.getTestCaseInput() instanceof ExecutableTestCaseInput) {
            //    		// Execute the testCase using exec()
            //    	}
            //    }

            for (TestCase testCase : testSuite.getTestCases()) {
                System.out.println("Executing test case: " + testCase.getName()); // DEBUG
                if (testCase.getTestCaseInput() instanceof HttpTestCaseInput) {
                    HttpTestCaseInput httpTestCaseInput =
                            (HttpTestCaseInput) testCase.getTestCaseInput();

                    HttpUriRequest attackRequest = httpTestCaseInput.buildAttackRequest();

                    // Send the next test case request with its attack payload
                    sendRequest(httpClient, attackRequest, true);
                } else if (testCase.getTestCaseInput() instanceof ExecutableTestCaseInput) {
                    ExecutableTestCaseInput executableTestCaseInput =
                            (ExecutableTestCaseInput) testCase.getTestCaseInput();

                    CliRequest attackRequest = executableTestCaseInput.buildAttackRequest();

                    // Send the next test case request with its attack payload
                    execute(attackRequest);
                }
            }

            // Log the elapsed time for all test cases
            long stop = System.currentTimeMillis();
            int seconds = (int) (stop - start) / 1000;

            Date now = new Date();

            System.out.printf(
                    "Crawl ran on %tF %<tT for %s v%s took %d seconds%n",
                    now, testSuite.getName(), testSuite.getVersion(), seconds);
        }
    }

    // This method taken directly from:
    // https://memorynotfound.com/ignore-certificate-errors-apache-httpclient/
    static CloseableHttpClient createAcceptSelfSignedCertificateClient()
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

    /**
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code. This is for normal, non-attack requests.
     *
     * @param httpclient - The HTTP client to use to make the request
     * @param request - THe HTTP request to issue
     */
    static ResponseInfo sendRequest(CloseableHttpClient httpclient, HttpUriRequest request) {
        return sendRequest(httpclient, request, false);
    }

    /**
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code.
     *
     * @param httpclient - The HTTP client to use to make the request
     * @param request - THe HTTP request to issue
     * @param attackRequest - true if this response info is associated with an attack request, false
     *     otherwise
     */
    static ResponseInfo sendRequest(
            CloseableHttpClient httpclient, HttpUriRequest request, boolean attackRequest) {
        HttpResponseInfo responseInfo = new HttpResponseInfo(attackRequest);
        //        responseInfo.setRequestBase(request);
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
        try {
            System.out.println((isPost ? "POST " : "GET ") + request.getUri());
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
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
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code. By default, this assumes a normal 'safe' request.
     *
     * @param request - The CLI request to issue
     */
    static ResponseInfo execute(CliRequest request) {
        return execute(request, false);
    }

    /**
     * Issue the requested request, measure the time required to execute, then output both to stdout
     * and the global variable timeString the URL tested, the time required to execute and the
     * response code.
     *
     * @param request - The CLI request to issue
     * @param attackRequest - True if executing an attack, false otherwise
     */
    static ResponseInfo execute(CliRequest request, boolean attackRequest) {
        CliResponseInfo responseInfo = new CliResponseInfo(attackRequest);
        responseInfo.setRequest(request);
        //        responseInfo.setRequestBase(request);

        ArrayList<String> executeArgs =
                new ArrayList<>(Arrays.asList(request.getCommand().split(" ")));
        for (RequestVariable arg : request.getArgs()) {
            //            System.out.println("Adding arg: " + arg.getValue());
            executeArgs.add(arg.getValue());
        }
        //        System.out.println(String.join(" ", executeArgs));

        StopWatch watch = new StopWatch();

        watch.start();
        try {
            //            response = httpclient.execute(request);
            ProcessBuilder builder = new ProcessBuilder(executeArgs);
            // FIXME: Do not hardcode this path
            builder.directory(new File("../../julietpy/testcode"));
            builder.redirectErrorStream(true);
            Process process = builder.start();
            try (BufferedReader reader =
                            new BufferedReader(new InputStreamReader(process.getInputStream()));
                    BufferedWriter writer =
                            new BufferedWriter(
                                    new OutputStreamWriter(process.getOutputStream())); ) {
                if (request.getStdinData() != null) {
                    writer.write(request.getStdinData().getValue());
                    writer.flush();
                    writer.close();
                }

                StringJoiner sj = new StringJoiner(System.getProperty("line.separator"));
                reader.lines().iterator().forEachRemaining(sj::add);
                String output = sj.toString();
                responseInfo.setResponseString(output);
                int exitValue = process.waitFor();
                //            attackPayloadResponseInfo = new ResponseInfo();
                //            System.out.printf("Program terminated with return code: %s%n",
                // exitValue);
                responseInfo.setStatusCode(exitValue);
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }
        watch.stop();

        return responseInfo;
    }

    /**
     * Process the command line arguments that make any configuration changes.
     *
     * @param args - args passed to main().
     * @return specified crawler file if valid command line arguments provided. Null otherwise.
     */
    protected void processCommandLineArgs(String[] args) {

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

    /**
     * The execute() method is invoked when this class is invoked as a maven plugin, rather than via
     * the command line. So what we do here is set up the command line parameters and then invoke
     * main() so this can be called both as a plugin, or via the command line.
     */
    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (null == this.pluginFilenameParam) {
            System.out.println("ERROR: A crawlerFile parameter must be specified.");
        } else {
            List<String> mainArgs = new ArrayList<>();
            mainArgs.add("-f");
            mainArgs.add(this.pluginFilenameParam);
            if (this.pluginTestCaseNameParam != null) {
                mainArgs.add("-n");
                mainArgs.add(this.pluginTestCaseNameParam);
            }
            main(mainArgs.stream().toArray(String[]::new));
        }
    }

    public static void main(String[] args) {
        // thisInstance can be set from execute() or here, depending on how this class is invoked
        // (via maven or command line)
        if (thisInstance == null) {
            thisInstance = new BenchmarkCrawler();
        }
        thisInstance.processCommandLineArgs(args);
        thisInstance.load();
        thisInstance.run();
    }
}
