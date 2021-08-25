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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.owasp.benchmarkutils.helpers.Utils;
import org.owasp.benchmarkutils.score.BenchmarkScore;

/**
 * TODO: Refactor this class. There is way too much duplication of code in BenchmarkCrawler here.
 */
@Mojo(
        name = "run-verification-crawler",
        requiresProject = false,
        defaultPhase = LifecyclePhase.COMPILE)
public class BenchmarkCrawlerVerification extends BenchmarkCrawler {

    private static int maxTimeInSeconds = 2;
    private static boolean isTimingEnabled = false;
    private static final String FILENAME_TIMES_ALL = "crawlerTimes.txt";
    private static final String FILENAME_TIMES = "crawlerSlowTimes.txt";
    private static final String FILENAME_NON_DISCRIMINATORY_LOG = "nonDiscriminatoryTestCases.txt";
    private static final String FILENAME_ERRORS_LOG = "errorTestCases.txt";
    private static final String FILENAME_UNVERIFIABLE_LOG = "unverifiableTestCases.txt";
    // The following is reconfigurable via parameters to main()
    private static String CRAWLER_DATA_DIR = Utils.DATA_DIR; // default data dir

    SimpleFileLogger tLogger;
    SimpleFileLogger ndLogger;
    SimpleFileLogger eLogger;
    SimpleFileLogger uLogger;

    BenchmarkCrawlerVerification() {
        // Default constructor required to support Maven plugin API.
        // The BenchmarkCrawlerVerification(File) must eventually be used before run()
        // is invoked on that instance of the Crawler.
    }

    BenchmarkCrawlerVerification(File file) {
        super(file);
    }

    @Override
    protected void crawl(List<AbstractTestCaseRequest> requests) throws Exception {
        CloseableHttpClient httpclient = createAcceptSelfSignedCertificateClient();
        long start = System.currentTimeMillis();
        List<ResponseInfo> responseInfoList = new ArrayList<ResponseInfo>();
        List<TestCaseVerificationResults> results = new ArrayList<TestCaseVerificationResults>();

        final File FILE_NON_DISCRIMINATORY_LOG =
                new File(CRAWLER_DATA_DIR, FILENAME_NON_DISCRIMINATORY_LOG);
        final File FILE_ERRORS_LOG = new File(CRAWLER_DATA_DIR, FILENAME_ERRORS_LOG);
        final File FILE_TIMES_LOG;
        if (isTimingEnabled) FILE_TIMES_LOG = new File(CRAWLER_DATA_DIR, FILENAME_TIMES);
        else FILE_TIMES_LOG = new File(CRAWLER_DATA_DIR, FILENAME_TIMES_ALL);
        final File FILE_UNVERIFIABLE_LOG = new File(CRAWLER_DATA_DIR, FILENAME_UNVERIFIABLE_LOG);
        SimpleFileLogger.setFile("TIMES", FILE_TIMES_LOG);
        SimpleFileLogger.setFile("NONDISCRIMINATORY", FILE_NON_DISCRIMINATORY_LOG);
        SimpleFileLogger.setFile("ERRORS", FILE_ERRORS_LOG);
        SimpleFileLogger.setFile("UNVERIFIABLE", FILE_UNVERIFIABLE_LOG);

        String completionMessage = null;

        try (SimpleFileLogger nl = SimpleFileLogger.getLogger("NONDISCRIMINATORY");
                SimpleFileLogger el = SimpleFileLogger.getLogger("ERRORS");
                SimpleFileLogger ul = SimpleFileLogger.getLogger("UNVERIFIABLE");
                SimpleFileLogger tl = SimpleFileLogger.getLogger("TIMES")) {

            ndLogger = nl;
            eLogger = el;
            uLogger = ul;
            tLogger = tl;

            for (AbstractTestCaseRequest request : requests) {
                // Send the next test case request with its attack payload
                ResponseInfo attackPayloadResponseInfo = sendRequest(httpclient, request);
                responseInfoList.add(attackPayloadResponseInfo);

                // Log the response
                log(attackPayloadResponseInfo);

                ResponseInfo safePayloadResponseInfo = null;
                if (!request.isUnverifiable()) {
                    // Send the next test case request with its safe payload
                    request.setSafe(true);
                    safePayloadResponseInfo = sendRequest(httpclient, request);
                    responseInfoList.add(safePayloadResponseInfo);

                    // Log the response
                    log(safePayloadResponseInfo);
                }

                TestCaseVerificationResults result =
                        new TestCaseVerificationResults(
                                request, attackPayloadResponseInfo, safePayloadResponseInfo);
                results.add(result);

                // Verify the response
                if (RegressionTesting.isTestingEnabled) {
                    handleResponse(result);
                }
            }

            // Log the elapsed time for all test cases
            long stop = System.currentTimeMillis();
            int seconds = (int) (stop - start) / 1000;

            Date now = new Date();

            completionMessage =
                    String.format(
                            "Verification crawl ran on %tF %<tT for %s v%s took %d seconds%n",
                            now,
                            BenchmarkScore.TESTSUITE,
                            BenchmarkScore.TESTSUITEVERSION,
                            seconds);
            tLogger.println(completionMessage);

            // Report the verified results
            if (RegressionTesting.isTestingEnabled) {
                RegressionTesting.genFailedTCFile(results, CRAWLER_DATA_DIR);

                if (!RegressionTesting.failedTruePositivesList.isEmpty()
                        || !RegressionTesting.failedFalsePositivesList.isEmpty()) {
                    eLogger.println();
                    eLogger.println("== Errors report ==");
                    eLogger.println();
                }

                if (!RegressionTesting.failedTruePositivesList.isEmpty()) {
                    eLogger.printf(
                            "== True Positive Test Cases with Errors [%d of %d] ==%n",
                            +RegressionTesting.failedTruePositives,
                            +RegressionTesting.truePositives);
                    eLogger.println();

                    for (AbstractTestCaseRequest request :
                            RegressionTesting.failedTruePositivesList.keySet()) {
                        eLogger.printf(
                                "%s: %s%n",
                                request.getName(),
                                RegressionTesting.failedTruePositivesList.get(request));
                    }
                }

                if (!RegressionTesting.failedFalsePositivesList.isEmpty()) {
                    if (!RegressionTesting.failedTruePositivesList.isEmpty()) {
                        eLogger.println();
                    }

                    eLogger.printf(
                            "== False Positive Test Cases with Errors [%d of %d] ==%n",
                            RegressionTesting.failedFalsePositives,
                            RegressionTesting.falsePositives);
                    eLogger.println();

                    for (AbstractTestCaseRequest request :
                            RegressionTesting.failedFalsePositivesList.keySet()) {
                        eLogger.printf(
                                "%s: %s%n",
                                request.getName(),
                                RegressionTesting.failedFalsePositivesList.get(request));
                    }
                }
            }
        }
        System.out.printf(
                "Details of non-discriminatory test cases written to: %s%n",
                FILE_NON_DISCRIMINATORY_LOG);
        System.out.printf(
                "Details of errors/exceptions in test cases written to: %s%n", FILE_ERRORS_LOG);
        System.out.printf(
                "Details of unverifiable test cases written to: %s%n", FILE_UNVERIFIABLE_LOG);
        System.out.printf("Test case time measurements written to: %s%n", FILE_TIMES_LOG);

        RegressionTesting.printCrawlSummary(results);
        System.out.println();
        System.out.println(completionMessage);
    }

    private void log(ResponseInfo responseInfo) throws IOException {
        // Log the response
        HttpUriRequest requestBase = responseInfo.getRequestBase();
        String outputString =
                String.format(
                        "--> (%d : %d sec)%n",
                        responseInfo.getStatusCode(), responseInfo.getTimeInSeconds());
        if (isTimingEnabled) {
            if (responseInfo.getTimeInSeconds() >= maxTimeInSeconds) {
                tLogger.println(requestBase.getMethod() + " " + requestBase.getURI());
                tLogger.println(outputString);
            }
        } else {
            tLogger.println(requestBase.getMethod() + " " + requestBase.getURI());
            tLogger.println(outputString);
        }
    }

    /**
     * For the verification crawler, processing the result means verifying whether the test case is
     * actually vulnerable or not, relative to whether it is supposed to be vulnerable. This method
     * has a side-affect of setting request.setPassed() for the current test case. Passing means it
     * was exploitable for a True Positive and appears to not be exploitable for a False Positive.
     *
     * @param result - The results required to verify this test case.
     * @throws FileNotFoundException
     * @throws LoggerConfigurationException
     */
    protected static void handleResponse(TestCaseVerificationResults result)
            throws FileNotFoundException, LoggerConfigurationException {

        // Check to see if this specific test case has a specified expected response value.
        // If so, run it through verification using it's specific attackSuccessIndicator.
        // Note that a specific success indicator overrides any generic category tests, if
        // specified.
        RegressionTesting.verifyTestCase(result);
    }

    /**
     * Process the command line arguments that make any configuration changes.
     *
     * @param args - args passed to main().
     * @return specified crawler file if valid command line arguments provided. Null otherwise.
     */
    private static File processCommandLineArgs(String[] args) {

        // Set default location
        String crawlerFileName = new File(Utils.DATA_DIR, "benchmark-attack-http.xml").getPath();
        File crawlerFile = new File(crawlerFileName);

        RegressionTesting.isTestingEnabled = true;

        if (args != null) {
            int time_val_index = -1;

            for (int i = 0; i < args.length; i++) {
                if ("-time".equals(args[i])) {
                    isTimingEnabled = true;
                    time_val_index = ++i; // Advance to index of time value
                } else if ("-f".equalsIgnoreCase(args[i])) {
                    // -f indicates use the specified crawler file
                    crawlerFileName = args[++i];
                    crawlerFile = new File(crawlerFileName);
                } else if (!(args[0] == null
                        && args[1]
                                == null)) { // pom settings for crawler forces creation of 2 args,
                    System.out.println(
                            "ERROR: Unrecognized parameter to verification crawler: " + args[i]);
                    System.out.println(
                            "Supported options: -f /PATH/TO/TESTSUITE-attack-http.xml -time MAXTIMESECONDS");
                    return null;
                }
            }

            if (time_val_index > -1) {
                try {
                    maxTimeInSeconds = Integer.parseInt(args[time_val_index]);
                    System.out.println("Setting timeout for test case to: " + maxTimeInSeconds);
                } catch (NumberFormatException e) {
                    System.out.println(
                            "ERROR: -time value must be an integer (in seconds), not: "
                                    + args[time_val_index]);
                    return null;
                }
            }
        }

        if (crawlerFile != null) {
            if (!crawlerFile.exists()) {
                System.out.println(
                        "ERROR: Crawler Configuration file: '" + crawlerFileName + "' not found!");
                crawlerFile = null;
            } else {
                // Crawler output files go into the same dir where the crawler config files are
                CRAWLER_DATA_DIR = crawlerFile.getParent() + File.separator;
            }
        }

        return crawlerFile;
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (null == crawlerFileName) {
            System.out.println("ERROR: A verification crawler file must be specified.");
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

        BenchmarkCrawlerVerification crawler = new BenchmarkCrawlerVerification(crawlerFile);
        crawler.run();
    }
}
