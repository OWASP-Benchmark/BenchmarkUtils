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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.owasp.benchmarkutils.helpers.TestSuite;
import org.owasp.benchmarkutils.helpers.Utils;

/**
 * V2 verification crawler that extends {@link BenchmarkCrawler_newv2} to send both attack and safe
 * requests per test case and verify whether the exploit succeeded.
 *
 * <p>Inherits the configurable timeout ({@code -T}) and CLI execution support from the parent. Also
 * supports the {@code -t} timing-threshold flag from the original {@link
 * BenchmarkCrawlerVerification}.
 *
 * <p>Resolves GitHub issues #3 (timeout) and #1 (command-line crawler/verification).
 */
@Mojo(
        name = "run-verification-crawler-v2",
        requiresProject = false,
        defaultPhase = LifecyclePhase.COMPILE)
public class BenchmarkCrawlerVerification_newv2 extends BenchmarkCrawler_newv2 {

    private static int maxTimeInSeconds = 2;
    private static boolean isTimingEnabled = false;

    private static final String FILENAME_TIMES_ALL = "crawlerTimes.txt";
    private static final String FILENAME_TIMES = "crawlerSlowTimes.txt";
    private static final String FILENAME_NON_DISCRIMINATORY_LOG = "nonDiscriminatoryTestCases.txt";
    private static final String FILENAME_ERRORS_LOG = "errorTestCases.txt";
    private static final String FILENAME_UNVERIFIABLE_LOG = "unverifiableTestCases.txt";

    private static String CRAWLER_DATA_DIR = Utils.DATA_DIR;

    SimpleFileLogger tLogger;
    SimpleFileLogger ndLogger;
    SimpleFileLogger eLogger;
    SimpleFileLogger uLogger;

    @Override
    protected void crawl(TestSuite testSuite) throws Exception {
        CloseableHttpClient httpclient = createHttpClient();
        long start = System.currentTimeMillis();
        List<ResponseInfo> responseInfoList = new ArrayList<>();
        List<TestCaseVerificationResults> httpResults = new ArrayList<>();
        List<TestCaseVerificationResults> cliResults = new ArrayList<>();

        final File FILE_NON_DISCRIMINATORY_LOG =
                new File(CRAWLER_DATA_DIR, FILENAME_NON_DISCRIMINATORY_LOG);
        final File FILE_ERRORS_LOG = new File(CRAWLER_DATA_DIR, FILENAME_ERRORS_LOG);
        final File FILE_TIMES_LOG;
        if (isTimingEnabled) {
            FILE_TIMES_LOG = new File(CRAWLER_DATA_DIR, FILENAME_TIMES);
        } else {
            FILE_TIMES_LOG = new File(CRAWLER_DATA_DIR, FILENAME_TIMES_ALL);
        }
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

            for (AbstractTestCaseRequest requestTemplate : testSuite.getTestCases()) {
                boolean isCli = requestTemplate instanceof CommandLineTestCaseRequest;

                ResponseInfo attackPayloadResponseInfo;
                ResponseInfo safePayloadResponseInfo = null;
                HttpUriRequest attackRequest = null;
                HttpUriRequest safeRequest = null;

                if (isCli) {
                    CommandLineTestCaseRequest cliReq =
                            (CommandLineTestCaseRequest) requestTemplate;
                    List<String> attackCmd = cliReq.buildCommand(false);
                    attackPayloadResponseInfo =
                            executeCommand(attackCmd, cliReq.getCommandDir(), networkTimeoutSeconds);
                    responseInfoList.add(attackPayloadResponseInfo);
                    logResponse(attackPayloadResponseInfo, "CMD " + String.join(" ", attackCmd));

                    if (!requestTemplate.isUnverifiable()) {
                        List<String> safeCmd = cliReq.buildCommand(true);
                        safePayloadResponseInfo =
                                executeCommand(
                                        safeCmd, cliReq.getCommandDir(), networkTimeoutSeconds);
                        responseInfoList.add(safePayloadResponseInfo);
                        logResponse(safePayloadResponseInfo, "CMD " + String.join(" ", safeCmd));
                    }
                } else {
                    attackRequest = requestTemplate.buildAttackRequest();
                    safeRequest = requestTemplate.buildSafeRequest();

                    attackPayloadResponseInfo = sendRequest(httpclient, attackRequest);
                    responseInfoList.add(attackPayloadResponseInfo);
                    logResponse(attackPayloadResponseInfo, attackRequest);

                    if (!requestTemplate.isUnverifiable()) {
                        safePayloadResponseInfo = sendRequest(httpclient, safeRequest);
                        responseInfoList.add(safePayloadResponseInfo);
                        logResponse(safePayloadResponseInfo, safeRequest);
                    }
                }

                TestCaseVerificationResults result =
                        new TestCaseVerificationResults(
                                attackRequest,
                                safeRequest,
                                requestTemplate,
                                attackPayloadResponseInfo,
                                safePayloadResponseInfo);

                if (RegressionTesting.isTestingEnabled) {
                    if (isCli) {
                        verifyCliTestCase(result);
                        cliResults.add(result);
                    } else {
                        handleResponse(result);
                        httpResults.add(result);
                    }
                } else {
                    if (isCli) cliResults.add(result);
                    else httpResults.add(result);
                }
            }

            long stop = System.currentTimeMillis();
            int seconds = (int) (stop - start) / 1000;
            Date now = new Date();

            completionMessage =
                    String.format(
                            "Verification crawl ran on %tF %<tT for %s v%s took %d seconds%n",
                            now, testSuite.getName(), testSuite.getVersion(), seconds);
            tLogger.println(completionMessage);

            if (RegressionTesting.isTestingEnabled) {
                List<TestCaseVerificationResults> allResults = new ArrayList<>(httpResults);
                allResults.addAll(cliResults);

                // genFailedTCFile calls printTestCaseDetails which calls printHttpRequest —
                // that NPEs on null HttpUriRequest. So we only pass HTTP results to it.
                // Then we supplement the static counters it sets with CLI results so
                // printCrawlSummary reports accurate totals.
                RegressionTesting.genFailedTCFile(httpResults, CRAWLER_DATA_DIR);
                supplementCountsWithCliResults(cliResults);

                printCliFailures(cliResults);

                if (!RegressionTesting.failedTruePositivesList.isEmpty()
                        || !RegressionTesting.failedFalsePositivesList.isEmpty()) {
                    eLogger.println();
                    eLogger.println("== Errors report ==");
                    eLogger.println();
                }

                if (!RegressionTesting.failedTruePositivesList.isEmpty()) {
                    eLogger.printf(
                            "== True Positive Test Cases with Errors [%d of %d] ==%n",
                            RegressionTesting.failedTruePositives,
                            RegressionTesting.truePositives);
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

        if (FILE_NON_DISCRIMINATORY_LOG.length() > 0) {
            System.out.printf(
                    "Details of non-discriminatory test cases written to: %s%n",
                    FILE_NON_DISCRIMINATORY_LOG);
        }
        if (FILE_ERRORS_LOG.length() > 0) {
            System.out.printf(
                    "Details of errors/exceptions in test cases written to: %s%n", FILE_ERRORS_LOG);
        }
        if (FILE_UNVERIFIABLE_LOG.length() > 0) {
            System.out.printf(
                    "Details of unverifiable test cases written to: %s%n", FILE_UNVERIFIABLE_LOG);
        }
        System.out.printf("Test case time measurements written to: %s%n", FILE_TIMES_LOG);

        List<TestCaseVerificationResults> allResults = new ArrayList<>(httpResults);
        allResults.addAll(cliResults);
        RegressionTesting.printCrawlSummary(allResults);
        System.out.println();
        System.out.println(completionMessage);
    }

    /**
     * Verify a CLI test case using {@link RegressionTesting#verifyResponse} directly. We avoid
     * calling {@link RegressionTesting#verifyTestCase} because it delegates to {@code
     * printTestCaseDetails} which calls {@code printHttpRequest} on the attackRequest/safeRequest
     * fields — those are null for CLI test cases.
     */
    private void verifyCliTestCase(TestCaseVerificationResults result)
            throws FileNotFoundException, LoggerConfigurationException {

        AbstractTestCaseRequest requestTemplate = result.getRequestTemplate();

        result.setUnverifiable(false);
        result.setDeclaredUnverifiable(false);

        if (requestTemplate.isUnverifiable()) {
            result.setUnverifiable(true);
            result.setDeclaredUnverifiable(true);
            uLogger.printf("UNVERIFIABLE (declared CLI): %s%n", requestTemplate.getName());
        } else if (requestTemplate.getAttackSuccessString() == null) {
            result.setUnverifiable(true);
            result.setDeclaredUnverifiable(false);
            uLogger.printf("UNVERIFIABLE (undeclared CLI): %s%n", requestTemplate.getName());
        }

        if (!result.isUnverifiable()) {
            boolean isAttackValueVerified =
                    RegressionTesting.verifyResponse(
                            result.getResponseToAttackValue().getResponseString(),
                            requestTemplate.getAttackSuccessString(),
                            requestTemplate.getAttackSuccessStringPresent());

            boolean isSafeValueVerified = false;
            if (result.getResponseToSafeValue() != null) {
                isSafeValueVerified =
                        RegressionTesting.verifyResponse(
                                result.getResponseToSafeValue().getResponseString(),
                                requestTemplate.getAttackSuccessString(),
                                requestTemplate.getAttackSuccessStringPresent());
            }

            if (requestTemplate.isVulnerability()) {
                if (isAttackValueVerified) {
                    result.setPassed(true);
                    if (isSafeValueVerified) {
                        ndLogger.printf(
                                "Non-discriminatory true positive CLI test %s: "
                                        + "attack-success-string found in both safe and attack "
                                        + "responses.%n",
                                requestTemplate.getName());
                    }
                } else {
                    result.setPassed(false);
                }
            } else {
                if (isAttackValueVerified) {
                    result.setPassed(false);
                } else {
                    result.setPassed(true);
                    if (isSafeValueVerified) {
                        ndLogger.printf(
                                "Non-discriminatory false positive CLI test %s: "
                                        + "attack-success-string found in safe response.%n",
                                requestTemplate.getName());
                    }
                }
            }
        }

        // Error detection (mirrors RegressionTesting.findErrors)
        List<String> reasons = new ArrayList<>();
        findCliErrors(result.getResponseToAttackValue(), "Attack value", reasons);
        findCliErrors(result.getResponseToSafeValue(), "Safe value", reasons);
        boolean hasErrors = !reasons.isEmpty();
        String compositeReason = "\t- " + String.join(", ", reasons);

        if (requestTemplate.isVulnerability()) {
            RegressionTesting.truePositives++;
            if (hasErrors) {
                RegressionTesting.failedTruePositives++;
                RegressionTesting.failedTruePositivesList.put(requestTemplate, compositeReason);
            }
        } else {
            RegressionTesting.falsePositives++;
            if (hasErrors) {
                RegressionTesting.failedFalsePositives++;
                RegressionTesting.failedFalsePositivesList.put(requestTemplate, compositeReason);
            }
        }
    }

    /**
     * Supplement the static counters in {@link RegressionTesting} that {@code genFailedTCFile} sets
     * (totalCount, passedCount, failedCount, etc.) with CLI test case results. This is necessary
     * because we only pass HTTP results to {@code genFailedTCFile} to avoid NPEs.
     */
    private static void supplementCountsWithCliResults(
            List<TestCaseVerificationResults> cliResults) {
        for (TestCaseVerificationResults result : cliResults) {
            RegressionTesting.totalCount++;
            if (result.isUnverifiable()) {
                if (result.isDeclaredUnverifiable()) {
                    RegressionTesting.declaredUnverifiable++;
                } else {
                    RegressionTesting.undeclaredUnverifiable++;
                }
            } else {
                RegressionTesting.verifiedCount++;
                if (result.isPassed()) {
                    if (result.getRequestTemplate().isVulnerability()) {
                        RegressionTesting.truePositivePassedCount++;
                    } else {
                        RegressionTesting.falsePositivePassedCount++;
                    }
                } else {
                    if (result.getRequestTemplate().isVulnerability()) {
                        RegressionTesting.truePositiveFailedCount++;
                    } else {
                        RegressionTesting.falsePositiveFailedCount++;
                    }
                }
            }
        }
    }

    private static void findCliErrors(
            ResponseInfo responseInfo, String prefix, List<String> reasons) {
        if (responseInfo != null) {
            if (responseInfo.getStatusCode() != 0) {
                reasons.add(prefix + " exit code: " + responseInfo.getStatusCode());
            }
            if (responseInfo.getResponseString().toLowerCase().contains("error")) {
                reasons.add(prefix + " output contains: error");
            } else if (responseInfo.getResponseString().toLowerCase().contains("exception")) {
                reasons.add(prefix + " output contains: exception");
            }
        }
    }

    private void printCliFailures(List<TestCaseVerificationResults> cliResults) {
        for (TestCaseVerificationResults result : cliResults) {
            if (!result.isUnverifiable() && !result.isPassed()) {
                AbstractTestCaseRequest req = result.getRequestTemplate();
                String msg =
                        String.format(
                                "FAILURE: %s positive %s CLI test %s%n",
                                req.isVulnerability() ? "True" : "False",
                                req.getCategory(),
                                req.getName());
                System.out.print(msg);
                eLogger.print(msg);

                eLogger.printf(
                        "  Attack output (exit %d): %s%n",
                        result.getResponseToAttackValue().getStatusCode(),
                        truncate(result.getResponseToAttackValue().getResponseString(), 500));
                if (result.getResponseToSafeValue() != null) {
                    eLogger.printf(
                            "  Safe output (exit %d): %s%n",
                            result.getResponseToSafeValue().getStatusCode(),
                            truncate(result.getResponseToSafeValue().getResponseString(), 500));
                }
                String negated =
                        req.getAttackSuccessStringPresent() ? "" : "Failure ";
                eLogger.printf(
                        "  Attack success %sindicator: -->%s<--%n",
                        negated, req.getAttackSuccessString());
                eLogger.printf("----------------------------------------------------------%n%n");
            }
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) return "null";
        return s.length() <= maxLen ? s : s.substring(0, maxLen) + "... [truncated]";
    }

    private static void handleResponse(TestCaseVerificationResults result)
            throws FileNotFoundException, LoggerConfigurationException {
        RegressionTesting.verifyTestCase(result);
    }

    private void logResponse(ResponseInfo responseInfo, HttpUriRequest request) throws IOException {
        String outputString =
                String.format(
                        "--> (%d : %d sec)%n",
                        responseInfo.getStatusCode(), responseInfo.getTimeInSeconds());
        try {
            String requestLine = request.getMethod() + " " + request.getUri();
            if (isTimingEnabled) {
                if (responseInfo.getTimeInSeconds() >= maxTimeInSeconds) {
                    tLogger.println(requestLine);
                    tLogger.println(outputString);
                }
            } else {
                tLogger.println(requestLine);
                tLogger.println(outputString);
            }
        } catch (URISyntaxException e) {
            String errMsg =
                    request.getMethod() + " COULDN'T LOG URI due to URISyntaxException";
            tLogger.println(errMsg);
            tLogger.println(outputString);
            System.out.println(errMsg);
            e.printStackTrace();
        }
    }

    private void logResponse(ResponseInfo responseInfo, String commandDescription) {
        String outputString =
                String.format(
                        "--> (exit %d : %d sec)%n",
                        responseInfo.getStatusCode(), responseInfo.getTimeInSeconds());
        if (isTimingEnabled) {
            if (responseInfo.getTimeInSeconds() >= maxTimeInSeconds) {
                tLogger.println(commandDescription);
                tLogger.println(outputString);
            }
        } else {
            tLogger.println(commandDescription);
            tLogger.println(outputString);
        }
    }

    @Override
    protected void processCommandLineArgs(String[] args) {
        File defaultAttackCrawlerFile = new File(Utils.DATA_DIR, "benchmark-attack-http.xml");
        if (defaultAttackCrawlerFile.exists()) {
            setCrawlerFile(defaultAttackCrawlerFile.getPath());
        }

        RegressionTesting.isTestingEnabled = true;

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        Options options = new Options();
        options.addOption(
                Option.builder("f")
                        .longOpt("file")
                        .desc("a TESTSUITE-attack-http.xml file")
                        .hasArg()
                        .required()
                        .build());
        options.addOption(Option.builder("h").longOpt("help").desc("Usage").build());
        options.addOption(
                Option.builder("n")
                        .longOpt("name")
                        .desc("testcase name (e.g. BenchmarkTestCase00025)")
                        .hasArg()
                        .build());
        options.addOption(
                Option.builder("t")
                        .longOpt("time")
                        .desc("testcase timing threshold (in seconds) for slow-request log")
                        .hasArg()
                        .type(Number.class)
                        .build());
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
                CRAWLER_DATA_DIR = this.theCrawlerFile.getParent() + File.separator;
            }
            if (line.hasOption("h")) {
                formatter.printHelp("BenchmarkCrawlerVerification_newv2", options, true);
            }
            if (line.hasOption("n")) {
                selectedTestCaseName = line.getOptionValue("n");
            }
            if (line.hasOption("t")) {
                maxTimeInSeconds = ((Number) line.getParsedOptionValue("t")).intValue();
                isTimingEnabled = true;
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
            formatter.printHelp("BenchmarkCrawlerVerification_newv2", options);
            throw new RuntimeException("Error parsing arguments: ", e);
        }
    }

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        if (thisInstance == null) thisInstance = this;

        if (null == this.crawlerFile) {
            System.out.println("ERROR: An attack crawlerFile parameter must be specified.");
            System.exit(-1);
        } else {
            String[] mainArgs = {"-f", this.crawlerFile};
            main(mainArgs);
        }
    }

    public static void main(String[] args) {
        if (thisInstance == null) {
            thisInstance = new BenchmarkCrawlerVerification_newv2();
        }
        thisInstance.processCommandLineArgs(args);
        thisInstance.load();
        thisInstance.run();
    }
}
