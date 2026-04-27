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
 */
package org.owasp.benchmarkutils.tools;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.helpers.DefaultValidationEventHandler;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.time.StopWatch;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.client5.http.ssl.NoopHostnameVerifier;
import org.apache.hc.client5.http.ssl.SSLConnectionSocketFactory;
import org.apache.hc.client5.http.ssl.TrustSelfSignedStrategy;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.hc.core5.util.Timeout;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.eclipse.persistence.jaxb.JAXBContextFactory;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.TestSuite;
import org.owasp.benchmarkutils.score.BenchmarkScore;

/**
 * V2 crawler that adds two capabilities over {@link BenchmarkCrawler}:
 *
 * <ol>
 *   <li><b>Configurable timeout</b> ({@code -T / --timeout}): response timeout in seconds, disabled
 *       by default (0 = wait indefinitely). Resolves GitHub issue #3.
 *   <li><b>Command-line test case execution</b>: test cases with {@code tcType="CLI"} are executed
 *       as subprocesses via {@link ProcessBuilder} instead of HTTP. Resolves GitHub issue #1.
 * </ol>
 *
 * <p>Existing HTTP test suites work identically — this is a drop-in replacement.
 */
@Mojo(name = "run-crawler-v2", requiresProject = false, defaultPhase = LifecyclePhase.COMPILE)
public class BenchmarkCrawler_newv2 extends BenchmarkCrawler {

    private static final long CONNECT_TIMEOUT_SECONDS = 30;

    /**
     * Response timeout in seconds. 0 means disabled (wait indefinitely). Set via {@code -T} CLI
     * flag.
     */
    protected long networkTimeoutSeconds = 0;

    @Override
    protected void crawl(TestSuite testSuite) throws Exception {
        CloseableHttpClient httpclient = createHttpClient();
        long start = System.currentTimeMillis();

        for (AbstractTestCaseRequest requestTemplate : testSuite.getTestCases()) {
            if (requestTemplate instanceof CommandLineTestCaseRequest) {
                CommandLineTestCaseRequest cliRequest =
                        (CommandLineTestCaseRequest) requestTemplate;
                List<String> command = cliRequest.buildCommand(true);
                ResponseInfo responseInfo =
                        executeCommand(command, cliRequest.getCommandDir(), networkTimeoutSeconds);
                logCommandResponse(command, responseInfo);
            } else {
                HttpUriRequest request = requestTemplate.buildSafeRequest();
                sendRequest(httpclient, request);
            }
        }

        long stop = System.currentTimeMillis();
        int seconds = (int) (stop - start) / 1000;
        Date now = new Date();
        System.out.printf(
                "Crawl ran on %tF %<tT for %s v%s took %d seconds%n",
                now, testSuite.getName(), testSuite.getVersion(), seconds);
    }

    /**
     * Create an HttpClient with configurable response timeout.
     *
     * <p>Connect and connection-request timeouts are always {@value #CONNECT_TIMEOUT_SECONDS}
     * seconds. Response timeout is controlled by {@link #networkTimeoutSeconds}: 0 means no timeout
     * (indefinite wait).
     */
    protected CloseableHttpClient createHttpClient()
            throws KeyManagementException, NoSuchAlgorithmException, KeyStoreException {

        SSLContext sslContext =
                SSLContextBuilder.create().loadTrustMaterial(new TrustSelfSignedStrategy()).build();

        HostnameVerifier allowAllHosts = new NoopHostnameVerifier();
        SSLConnectionSocketFactory connectionFactory =
                new SSLConnectionSocketFactory(sslContext, allowAllHosts);

        HttpClientConnectionManager cm =
                PoolingHttpClientConnectionManagerBuilder.create()
                        .setSSLSocketFactory(connectionFactory)
                        .build();

        RequestConfig.Builder configBuilder =
                RequestConfig.custom()
                        .setConnectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                        .setConnectionRequestTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS);

        if (networkTimeoutSeconds > 0) {
            configBuilder.setResponseTimeout(networkTimeoutSeconds, TimeUnit.SECONDS);
        } else {
            configBuilder.setResponseTimeout(Timeout.DISABLED);
        }

        RequestConfig config = configBuilder.build();

        HttpClientBuilder builder =
                HttpClients.custom()
                        .setDefaultRequestConfig(config)
                        .setConnectionManager(cm);

        String pHost = System.getProperty("proxyHost");
        String pPort = System.getProperty("proxyPort");
        if (pHost != null && pPort != null) {
            builder.setProxy(new HttpHost(pHost, Integer.parseInt(pPort)));
        }

        return builder.build();
    }

    /**
     * Execute a command-line test case as a subprocess.
     *
     * @param command the executable and its arguments.
     * @param workingDir working directory (null = inherit from JVM).
     * @param timeoutSeconds max seconds to wait for the process (0 = no limit).
     * @return a {@link ResponseInfo} where responseString is stdout+stderr, statusCode is the exit
     *     code (-1 on timeout or error), and timeInSeconds is wall-clock elapsed time.
     */
    protected static ResponseInfo executeCommand(
            List<String> command, String workingDir, long timeoutSeconds) {

        ResponseInfo responseInfo = new ResponseInfo();
        StopWatch watch = new StopWatch();

        System.out.println("CMD " + String.join(" ", command));

        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        if (workingDir != null && !workingDir.trim().isEmpty()) {
            pb.directory(new File(workingDir));
        }

        watch.start();
        try {
            Process process = pb.start();
            String output = readStream(process.getInputStream());

            boolean finished;
            if (timeoutSeconds > 0) {
                finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
                if (!finished) {
                    process.destroyForcibly();
                    output += "\n[TIMEOUT after " + timeoutSeconds + " seconds]";
                    System.out.println("TIMEOUT: Process killed after " + timeoutSeconds + "s");
                }
            } else {
                process.waitFor();
                finished = true;
            }

            responseInfo.setResponseString(output);
            responseInfo.setStatusCode(finished ? process.exitValue() : -1);
        } catch (IOException e) {
            System.out.println("ERROR: Failed to execute command: " + e.getMessage());
            e.printStackTrace();
            responseInfo.setResponseString("ERROR: " + e.getMessage());
            responseInfo.setStatusCode(-1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            responseInfo.setResponseString("INTERRUPTED");
            responseInfo.setStatusCode(-1);
        }
        watch.stop();

        int seconds = (int) watch.getTime() / 1000;
        responseInfo.setTimeInSeconds(seconds);
        System.out.printf("--> (exit %d : %d sec)%n", responseInfo.getStatusCode(), seconds);
        return responseInfo;
    }

    private static String readStream(InputStream stream) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader =
                new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (sb.length() > 0) sb.append('\n');
                sb.append(line);
            }
        }
        return sb.toString();
    }

    private void logCommandResponse(List<String> command, ResponseInfo responseInfo) {
        // stdout logging already handled in executeCommand(); nothing extra needed for basic crawl.
    }

    /**
     * Load test suite from XML, using an extended JAXB context that recognizes {@code tcType="CLI"}
     * test cases via {@link CommandLineTestCaseRequest}.
     */
    @Override
    void load() {
        try {
            InputStream categoriesFileStream =
                    BenchmarkScore.class
                            .getClassLoader()
                            .getResourceAsStream(Categories.FILENAME);
            new Categories(categoriesFileStream);

            this.testSuite = parseHttpFileWithCliSupport(this.theCrawlerFile);

            Collections.sort(
                    this.testSuite.getTestCases(), AbstractTestCaseRequest.getNameComparator());

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

    /**
     * Parse an XML crawler file using a JAXB context that includes {@link
     * CommandLineTestCaseRequest} in addition to the standard HTTP request types.
     */
    static TestSuite parseHttpFileWithCliSupport(File file) throws Exception {
        JAXBContext context =
                JAXBContextFactory.createContext(
                        new Class[] {TestSuite.class, CommandLineTestCaseRequest.class}, null);
        Unmarshaller unmarshaller = context.createUnmarshaller();
        unmarshaller.setEventHandler(new DefaultValidationEventHandler());
        return (TestSuite) unmarshaller.unmarshal(new FileReader(file));
    }

    @Override
    protected void processCommandLineArgs(String[] args) {
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

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
                        .desc("testcase name (e.g. BenchmarkTestCase00025)")
                        .hasArg()
                        .build());
        options.addOption(Option.builder("h").longOpt("help").desc("Usage").build());
        options.addOption(
                Option.builder("T")
                        .longOpt("timeout")
                        .desc(
                                "Response timeout in seconds per request."
                                        + " 0 = no timeout (default)."
                                        + " Example: -T 300 for 5 minutes.")
                        .hasArg()
                        .type(Number.class)
                        .build());

        try {
            CommandLine line = parser.parse(options, args);

            if (line.hasOption("f")) {
                setCrawlerFile(line.getOptionValue("f"));
            }
            if (line.hasOption("h")) {
                formatter.printHelp("BenchmarkCrawler_newv2", options, true);
            }
            if (line.hasOption("n")) {
                selectedTestCaseName = line.getOptionValue("n");
            }
            if (line.hasOption("T")) {
                networkTimeoutSeconds =
                        ((Number) line.getParsedOptionValue("T")).longValue();
                if (networkTimeoutSeconds < 0) {
                    System.out.println(
                            "WARNING: Negative timeout value ignored, using 0 (no timeout).");
                    networkTimeoutSeconds = 0;
                }
                if (networkTimeoutSeconds > 0) {
                    System.out.printf(
                            "Response timeout set to %d seconds.%n", networkTimeoutSeconds);
                }
            }
        } catch (ParseException e) {
            formatter.printHelp("BenchmarkCrawler_newv2", options);
            throw new RuntimeException("Error parsing arguments: ", e);
        }
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (thisInstance == null) thisInstance = this;

        if (null == this.crawlerFile) {
            System.out.println("ERROR: A crawlerFile parameter must be specified.");
            System.exit(-1);
        } else {
            String[] mainArgs = {"-f", this.crawlerFile};
            main(mainArgs);
        }
    }

    public static void main(String[] args) {
        if (thisInstance == null) {
            thisInstance = new BenchmarkCrawler_newv2();
        }
        thisInstance.processCommandLineArgs(args);
        thisInstance.load();
        thisInstance.run();
    }
}
