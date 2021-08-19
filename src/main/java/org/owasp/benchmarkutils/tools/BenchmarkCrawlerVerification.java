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
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.http.client.methods.HttpRequestBase;
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

    private static List<String> crawlerOutputString = new ArrayList<String>();
    private static int maxTimeInSeconds = 2;
    private static boolean isTimingEnabled = false;
    private static final String CRAWLER_TIMES_FILE_ALL = "crawlerTimes.txt";
    private static final String CRAWLER_TIMES_FILE = "crawlerSlowTimes.txt";
    // The following is reconfigurable via parameters to main()
    private static String CRAWLER_TIMES_PATH = Utils.DATA_DIR; // default data dir

    BenchmarkCrawlerVerification() {
        // Default constructor required for to support Maven plugin API.
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
        ResponseInfo responseInfo = new ResponseInfo();
        HttpRequestBase requestBase = null;

        for (AbstractTestCaseRequest request : requests) {
            try {
                responseInfo = sendRequest(httpclient, request);
                requestBase = responseInfo.getRequestBase();
                String outputString =
                        "--> ("
                                + String.valueOf(responseInfo.getStatusCode())
                                + " : "
                                + responseInfo.getTime()
                                + " sec) ";
                if (isTimingEnabled) {
                    if (responseInfo.getTime() >= maxTimeInSeconds) {
                        crawlerOutputString.add(
                                requestBase.getMethod() + " " + requestBase.getURI());
                        crawlerOutputString.add(outputString);
                    }
                } else {
                    crawlerOutputString.add(requestBase.getMethod() + " " + requestBase.getURI());
                    crawlerOutputString.add(outputString);
                }

                if (RegressionTesting.isTestingEnabled) {
                    handleResponse(
                            request,
                            responseInfo.getResponseString(),
                            responseInfo.getStatusCode());
                }

                responseInfoList.add(responseInfo);
            } catch (Exception e) {
                System.err.println("\n  FAILED: " + e.getMessage());
                e.printStackTrace();
            }
        }
        long stop = System.currentTimeMillis();
        double seconds = (stop - start) / 1000;

        DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
        Date date = new Date();

        String completionmsg =
                "Verification crawl ran on "
                        + dateFormat.format(date)
                        + " for "
                        + BenchmarkScore.TESTSUITE
                        + " v"
                        + BenchmarkScore.TESTSUITEVERSION
                        + " took "
                        + seconds
                        + " seconds";
        crawlerOutputString.add(completionmsg);

        String fileToWrite = "";
        if (isTimingEnabled) fileToWrite = CRAWLER_TIMES_PATH + CRAWLER_TIMES_FILE;
        else fileToWrite = CRAWLER_TIMES_PATH + CRAWLER_TIMES_FILE_ALL;
        Files.createDirectories(Paths.get(CRAWLER_TIMES_PATH));
        Path outputFile = Paths.get(fileToWrite);

        Utils.writeToFile(outputFile, crawlerOutputString, false);

        if (RegressionTesting.isTestingEnabled) {
            RegressionTesting.genFailedTCFile(requests, responseInfoList, CRAWLER_TIMES_PATH);

            if (!RegressionTesting.failedTruePositivesList.isEmpty()
                    || !RegressionTesting.failedFalsePositivesList.isEmpty()) {
                System.out.println("\n== Errors report ==\n");
            }

            if (!RegressionTesting.failedTruePositivesList.isEmpty()) {
                System.out.println(
                        "== True Positive Test Cases with Errors ["
                                + RegressionTesting.failedTruePositives
                                + " of "
                                + RegressionTesting.truePositives
                                + "] ==\n");

                for (AbstractTestCaseRequest request :
                        RegressionTesting.failedTruePositivesList.keySet()) {
                    System.out.println(
                            request.getName()
                                    + ": "
                                    + RegressionTesting.failedTruePositivesList.get(request));
                }
            }

            if (!RegressionTesting.failedFalsePositivesList.isEmpty()) {
                if (!RegressionTesting.failedTruePositivesList.isEmpty()) {
                    System.out.println("");
                }

                System.out.println(
                        "== False Positive Test Cases with Errors ["
                                + RegressionTesting.failedFalsePositives
                                + " of "
                                + RegressionTesting.falsePositives
                                + "] ==\n");

                for (AbstractTestCaseRequest request :
                        RegressionTesting.failedFalsePositivesList.keySet()) {
                    System.out.println(
                            request.getName()
                                    + ": "
                                    + RegressionTesting.failedFalsePositivesList.get(request));
                }
            }
        }

        System.out.println("\n" + completionmsg);
    }

    /**
     * For the verification crawler, handling the response means verifying whether the test case is
     * actually vulnerable or not, relative to whether it is supposed to be vulnerable. The
     * verification technique depends on the CWE being verified. This method has a side-affect of
     * setting request.setPassed() for the current test case. Passing means it was exploitable for a
     * True Positive and appears to not be exploitable for a False Positive.
     *
     * @param request - The TestCaseRequest for this test case.
     * @param responseString - A copy of the response returned when invoking this test case.
     * @param statusCode - The status code returned by the response.
     */
    protected static void handleResponse(
            AbstractTestCaseRequest request, String responseString, int statusCode) {

        // Check to see if this specific test case has a specified expected response value.
        // If so, run it through verification using it's specific attackSuccessIndicator.
        // Note that a specific success indicator overrides any generic category tests, if
        // specified.
        String attackSuccessIndicator = request.getAttackSuccessString();
        if (attackSuccessIndicator != null) {
            RegressionTesting.verifyTestCase(
                    request, responseString, attackSuccessIndicator, statusCode);
        }
    }

    /**
     * Process the command line arguments that make any configuration changes.
     *
     * @param args - args passed to main().
     * @return specified crawler file if valid command line arguments provided. Null otherwise.
     */
    private static File processCommandLineArgs(String[] args) {

        String crawlerFileName = Utils.DATA_DIR + "benchmark-attack-http.xml"; // default location
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
                CRAWLER_TIMES_PATH = crawlerFile.getParent() + File.separator;
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
