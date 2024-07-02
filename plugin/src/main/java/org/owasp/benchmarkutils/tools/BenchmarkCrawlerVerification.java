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
import java.util.stream.Collectors;
import javax.xml.bind.JAXBException;
import javax.xml.parsers.ParserConfigurationException;
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
import org.apache.maven.plugins.annotations.Parameter;
import org.owasp.benchmarkutils.entities.CliRequest;
import org.owasp.benchmarkutils.entities.CliResponseInfo;
import org.owasp.benchmarkutils.entities.ExecutableTestCaseInput;
import org.owasp.benchmarkutils.entities.HttpResponseInfo;
import org.owasp.benchmarkutils.entities.HttpTestCaseInput;
import org.owasp.benchmarkutils.entities.ResponseInfo;
import org.owasp.benchmarkutils.entities.TestCase;
import org.owasp.benchmarkutils.entities.TestCaseSetup;
import org.owasp.benchmarkutils.entities.TestCaseSetupException;
import org.owasp.benchmarkutils.entities.TestSuite;
import org.owasp.benchmarkutils.helpers.Utils;
import org.xml.sax.SAXException;

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
    // private boolean verifyFixed = false; // DEBUG
    private String configurationDirectory = Utils.DATA_DIR;
    private String outputDirectory = Utils.DATA_DIR;
    //    private String beforeFixOutputDirectory =
    //            new File(new File(Utils.DATA_DIR).getParent(), "before_data")
    //                    .getAbsolutePath(); // DEBUG: Utils.DATA_DIR;
    private static final String FILENAME_TIMES_ALL = "crawlerTimes.txt";
    private static final String FILENAME_TIMES = "crawlerSlowTimes.txt";
    private static final String FILENAME_NON_DISCRIMINATORY_LOG = "nonDiscriminatoryTestCases.txt";
    private static final String FILENAME_ERRORS_LOG = "errorTestCases.txt";
    private static final String FILENAME_UNVERIFIABLE_LOG = "unverifiableTestCases.txt";
    // FIXME: This constant is also used by RegressionUtils and should not be duplicated.
    private static final String FILENAME_TC_VERIF_RESULTS_JSON = "testCaseVerificationResults.json";
    //     The following is reconfigurable via parameters to main()
    //    private String CRAWLER_DATA_DIR = Utils.DATA_DIR; // default data dir

    SimpleFileLogger tLogger;
    SimpleFileLogger ndLogger;
    SimpleFileLogger eLogger;
    SimpleFileLogger uLogger;

    @Parameter(property = "json", defaultValue = "false")
    private String generateJSONResults;

    @Parameter(property = "verifyFixed", defaultValue = "false")
    private String verifyFixed;

    @Parameter(property = "beforeFixOutputDirectory")
    private String beforeFixOutputDirectory;

    @Parameter(property = "testCaseName")
    private String selectedTestCaseName;

    BenchmarkCrawlerVerification() {
        // A default constructor required to support Maven plugin API.
        // The theCrawlerFile has to be instantiated before a crawl can be done.
    }

    @Override
    protected void crawl(TestSuite testSuite) throws Exception {

        // FIXME: Initialize all setup resources that are required
        // List<TestCaseSetup> setups = getTestCaseSetups(testSuite);
        // initializeSetups(setups);
        try (CloseableHttpClient httpClient = createAcceptSelfSignedCertificateClient()) {

            long start = System.currentTimeMillis();
            List<ResponseInfo> responseInfoList = new ArrayList<ResponseInfo>();
            List<TestCaseVerificationResults> results =
                    new ArrayList<TestCaseVerificationResults>();

            final File FILE_NON_DISCRIMINATORY_LOG =
                    new File(getOutputDirectory(), FILENAME_NON_DISCRIMINATORY_LOG);
            final File FILE_ERRORS_LOG = new File(getOutputDirectory(), FILENAME_ERRORS_LOG);
            final File FILE_TIMES_LOG;
            if (isTimingEnabled) {
                FILE_TIMES_LOG = new File(getOutputDirectory(), FILENAME_TIMES);
            } else {
                FILE_TIMES_LOG = new File(getOutputDirectory(), FILENAME_TIMES_ALL);
            }
            final File FILE_UNVERIFIABLE_LOG =
                    new File(getOutputDirectory(), FILENAME_UNVERIFIABLE_LOG);
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

                List<TestCase> filteredList;
                if (selectedTestCaseName != null) {
                    filteredList =
                            testSuite.getTestCases().stream()
                                    .filter(
                                            testCase ->
                                                    testCase.getName().equals(selectedTestCaseName))
                                    .collect(Collectors.toList());
                } else {
                    filteredList = testSuite.getTestCases();
                }
                for (TestCase testCase : filteredList) {

                    //                    if (this.selectedTestCaseName != null) {
                    //                        if
                    // (!testCase.getName().equals(this.selectedTestCaseName)) {
                    //                            continue;
                    //                        }
                    //                    }

                    // TestCaseVerificationResults result = testCase.execute();
                    // results.add(result);

                    TestExecutor attackExecutor = null;
                    TestExecutor safeExecutor = null;
                    ResponseInfo attackPayloadResponseInfo = null;
                    ResponseInfo safePayloadResponseInfo = null;
                    if (testCase.getTestCaseInput() instanceof HttpTestCaseInput) {
                        HttpTestCaseInput httpTestCaseInput =
                                (HttpTestCaseInput) testCase.getTestCaseInput();

                        // TestExecutor attackTestExecutor =
                        // httpTestCase.getTestCaseInput().buildAttackExecutor();
                        // TestExecutor safeTestExecutor =
                        // httpTestCase.getTestCaseInput().buildSafeExecutor();

                        // FIXME: What would the executable testcase's attackRequest look like?
                        HttpUriRequest attackRequest = httpTestCaseInput.buildAttackRequest();
                        HttpUriRequest safeRequest = httpTestCaseInput.buildSafeRequest();
                        attackExecutor = new HttpExecutor(attackRequest);
                        safeExecutor = new HttpExecutor(safeRequest);

                        // Send the next test case request with its attack payload
                        attackPayloadResponseInfo = sendRequest(httpClient, attackRequest, true);
                        responseInfoList.add(attackPayloadResponseInfo);

                        // Log the response
                        log(attackPayloadResponseInfo);

                        safePayloadResponseInfo = null;
                        if (!testCase.isUnverifiable()) {
                            // Send the next test case request with its safe payload
                            safePayloadResponseInfo = sendRequest(httpClient, safeRequest);
                            responseInfoList.add(safePayloadResponseInfo);

                            // Log the response
                            log(safePayloadResponseInfo);
                        }

                        //		                TestCaseVerificationResults result =
                        //		                        new TestCaseVerificationResults(
                        //		                        		attackExecutor,
                        //		                        		safeExecutor,
                        //		                                httpTestCase,
                        //		                                attackPayloadResponseInfo,
                        //		                                safePayloadResponseInfo);
                        //		                results.add(result);
                        //
                        //		                // Verify the response
                        //		                if (RegressionTesting.isTestingEnabled) {
                        //		                    handleResponse(result);
                        //		                }
                    } else if (testCase.getTestCaseInput() instanceof ExecutableTestCaseInput) {
                        ExecutableTestCaseInput executableTestCaseInput =
                                (ExecutableTestCaseInput) testCase.getTestCaseInput();

                        // FIXME: A bit of a hack
                        CliRequest attackRequest = executableTestCaseInput.buildAttackRequest();
                        CliRequest safeRequest = executableTestCaseInput.buildSafeRequest();
                        attackExecutor = new CliExecutor(attackRequest);
                        safeExecutor = new CliExecutor(safeRequest);

                        // Send the next test case request with its attack payload
                        System.out.println("Executing attack request: " + attackRequest);
                        attackPayloadResponseInfo = execute(attackRequest, true);
                        ////		                executeArgs.add(payload);
                        //		                ProcessBuilder builder = new
                        // ProcessBuilder(executeArgs);
                        //		                final Process process = builder.start();
                        //		                int exitValue = process.waitFor();
                        //		                attackPayloadResponseInfo = new ResponseInfo();
                        //		                System.out.printf("Program terminated with return code:
                        // %s%n", exitValue);
                        responseInfoList.add(attackPayloadResponseInfo);

                        // Log the response
                        log(attackPayloadResponseInfo);

                        safePayloadResponseInfo = null;
                        if (!testCase.isUnverifiable()) {
                            // Send the next test case request with its safe payload
                            System.out.println("Executing safe request: " + safeRequest);
                            safePayloadResponseInfo = execute(safeRequest);
                            responseInfoList.add(safePayloadResponseInfo);

                            // Log the response
                            log(safePayloadResponseInfo);
                        }

                        //		                TestCaseVerificationResults result =
                        //		                        new TestCaseVerificationResults(
                        //		                                attackRequest,
                        //		                                safeRequest,
                        //		                                cliTestCase,
                        //		                                attackPayloadResponseInfo,
                        //		                                safePayloadResponseInfo);
                        //		                results.add(result);
                        //
                        //		                // Verify the response
                        //		                if (RegressionTesting.isTestingEnabled) {
                        //		                    handleResponse(result);
                        //		                }
                    }
                    TestCaseVerificationResults result =
                            new TestCaseVerificationResults(
                                    attackExecutor.getExecutorDescription(),
                                    safeExecutor.getExecutorDescription(),
                                    testCase,
                                    attackPayloadResponseInfo,
                                    safePayloadResponseInfo);
                    results.add(result);

                    // Verify the response
                    if (RegressionTesting.isTestingEnabled) {
                        handleResponse(result);
                    }
                }
                TestCaseVerificationResultsCollection resultsCollection =
                        new TestCaseVerificationResultsCollection();
                resultsCollection.setResultsObjects(results);

                // Log the elapsed time for all test cases
                long stop = System.currentTimeMillis();
                int seconds = (int) (stop - start) / 1000;

                Date now = new Date();

                completionMessage =
                        String.format(
                                "Verification crawl ran on %tF %<tT for %s v%s took %d seconds%n",
                                now, testSuite.getName(), testSuite.getVersion(), seconds);
                tLogger.println(completionMessage);

                // Report the verified results
                if (RegressionTesting.isTestingEnabled) {
                    // Generate all the standard text file verification results to different files
                    RegressionTesting.genFailedTCFile(results, getOutputDirectory());

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

                        for (TestCase request :
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

                        for (TestCase request :
                                RegressionTesting.failedFalsePositivesList.keySet()) {
                            eLogger.printf(
                                    "%s: %s%n",
                                    request.getName(),
                                    RegressionTesting.failedFalsePositivesList.get(request));
                        }
                    }

                    // Then generate JSON file with ALL verification results if generateJSONResults
                    // is enabled. This has to go at end because previous methods have some side
                    // affects that fill in test case verification values.
                    RegressionTesting.genAllTCResultsToJsonFile(
                            resultsCollection,
                            getOutputDirectory(),
                            Boolean.parseBoolean(generateJSONResults));
                }
            }

            if (FILE_NON_DISCRIMINATORY_LOG.length() > 0) {
                System.out.printf(
                        "Details of non-discriminatory test cases written to: %s%n",
                        FILE_NON_DISCRIMINATORY_LOG);
            }
            if (FILE_ERRORS_LOG.length() > 0) {
                System.out.printf(
                        "Details of errors/exceptions in test cases written to: %s%n",
                        FILE_ERRORS_LOG);
            }
            if (FILE_UNVERIFIABLE_LOG.length() > 0) {
                System.out.printf(
                        "Details of unverifiable test cases written to: %s%n",
                        FILE_UNVERIFIABLE_LOG);
            }

            System.out.printf("Test case time measurements written to: %s%n", FILE_TIMES_LOG);

            RegressionTesting.printCrawlSummary(results);
            System.out.println();
            System.out.println(completionMessage);
        }

        // FIXME: Use a finally to cleanup all setup resources that were required
        // cleanupSetups(setups);
    }

    /**
     * @param testSuite
     * @throws Exception
     */
    protected void crawlToVerifyFix(TestSuite testSuite, String beforeFixOutputDirectory)
            throws Exception {

        // Get config directory for RUN 1 from CLI option
        // Get output directory for RUN 1
        // Get test case directory of RUN 2 from CLI option
        // Get output directory for RUN 2
        // Create a copy of TestSuite from the RUN 1 config
        // Modify TestSuite object so that every TestCase has isVulnerability = false
        // Call crawl(TestSuite) on the new TestSuite
        // Compare output of RUN 1 to output of RUN 2 and report result
    }

    private List<TestCaseSetup> getTestCaseSetups(TestSuite testSuite) {
        List<TestCaseSetup> testCaseSetups = new ArrayList<TestCaseSetup>();
        for (TestCase testCase : testSuite.getTestCases()) {
            TestCaseSetup testCaseSetup = testCase.getTestCaseSetup();
            if (testCaseSetup != null) {
                testCaseSetups.add(testCaseSetup);
            }
        }

        return testCaseSetups;
    }

    private void initializeSetups(List<TestCaseSetup> testCaseSetups)
            throws TestCaseSetupException {
        for (TestCaseSetup testCaseSetup : testCaseSetups) {
            testCaseSetup.setup();
        }
    }

    private void cleanupSetups(List<TestCaseSetup> testCaseSetups) throws TestCaseSetupException {
        for (TestCaseSetup testCaseSetup : testCaseSetups) {
            testCaseSetup.close();
        }
    }

    protected String getConfigurationDirectory() {
        return configurationDirectory;
    }

    protected String getOutputDirectory() {
        return outputDirectory;
    }

    private void log(ResponseInfo responseInfo) throws IOException {
        if (responseInfo instanceof HttpResponseInfo) {
            HttpResponseInfo httpResponseInfo = (HttpResponseInfo) responseInfo;

            // Log the response
            //            HttpUriRequest requestBase = httpResponseInfo.getRequestBase();
            String outputString =
                    String.format(
                            "--> (%d : %d sec)%n",
                            httpResponseInfo.getStatusCode(), httpResponseInfo.getTimeInSeconds());
            if (isTimingEnabled) {
                if (httpResponseInfo.getTimeInSeconds() >= maxTimeInSeconds) {
                    tLogger.println(httpResponseInfo.getMethod() + " " + httpResponseInfo.getUri());
                    tLogger.println(outputString);
                }
            } else {
                tLogger.println(httpResponseInfo.getMethod() + " " + httpResponseInfo.getUri());
                tLogger.println(outputString);
            }

        } else if (responseInfo instanceof CliResponseInfo) {
            CliResponseInfo cliResponseInfo = (CliResponseInfo) responseInfo;

            // Log the response
            CliRequest request = cliResponseInfo.getRequest();
            String responseString =
                    String.format(
                            "--> (%d : %d sec)%n",
                            cliResponseInfo.getStatusCode(), cliResponseInfo.getTimeInSeconds());
            if (isTimingEnabled) {
                if (cliResponseInfo.getTimeInSeconds() >= maxTimeInSeconds) {
                    tLogger.println(request.getCommand());
                    tLogger.println(responseString);
                }
            } else {
                tLogger.println(request.getCommand());
                tLogger.println(responseString);
            }
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
    protected void handleResponse(TestCaseVerificationResults results)
            throws FileNotFoundException, LoggerConfigurationException {

        // Check to see if this specific test case has a specified expected response value.
        // If so, run it through verification using it's specific attackSuccessIndicator.
        // Note that a specific success indicator overrides any generic category tests, if
        // specified.
        RegressionTesting.verifyTestCase(results);

        if (Boolean.parseBoolean(verifyFixed)) {
            TestCaseVerificationResultsCollection beforeFixResultsCollection =
                    loadTestCaseVerificationResults(beforeFixOutputDirectory);
            TestCaseVerificationResults beforeFixResults =
                    beforeFixResultsCollection.getResultsObjects().get(0);
            verifyFix(beforeFixResults, results);
        }
    }

    private TestCaseVerificationResultsCollection loadTestCaseVerificationResults(
            String directory) {

        TestCaseVerificationResultsCollection results = null;
        try {
            results =
                    Utils.jsonToTestCaseVerificationResultsList(
                            new File(directory, FILENAME_TC_VERIF_RESULTS_JSON));
        } catch (JAXBException
                | FileNotFoundException
                | SAXException
                | ParserConfigurationException e) {
            System.out.println("ERROR: Could not unmarshall JSON file content.");
            e.printStackTrace();
        }

        // FIXME: Replace this with code to load results from JSON data files
        //        TestExecutor attackTestExecutor = new HttpExecutor(null);
        //        TestExecutor safeTestExecutor = new HttpExecutor(null);
        //        TestCase testCase = new TestCase();
        //        ResponseInfo responseToAttackValue = new HttpResponseInfo(); // FIXME: Or
        // CliResponseInfo
        //        responseToAttackValue.setResponseString("");
        //        ResponseInfo responseToSafeValue = new HttpResponseInfo();
        //        responseToSafeValue.setResponseString("");
        //        TestCaseVerificationResults results =
        //                new TestCaseVerificationResults(
        //                        attackTestExecutor,
        //                        safeTestExecutor,
        //                        testCase,
        //                        responseToAttackValue,
        //                        responseToSafeValue);

        return results;
    }

    private boolean verifyFix(
            TestCaseVerificationResults beforeFixResults,
            TestCaseVerificationResults afterFixResults) {

        boolean wasExploited =
                afterFixResults.getTestCase().isVulnerability()
                        && !afterFixResults.getTestCase().isUnverifiable()
                        && afterFixResults.isPassed();
        boolean wasBroken =
                !beforeFixResults
                        .getResponseToSafeValue()
                        .getResponseString()
                        .equals(afterFixResults.getResponseToAttackValue().getResponseString());
        if (wasExploited) {
            System.out.println("NOT FIXED: Vulnerability was exploited");
        }
        if (wasBroken) {
            System.out.println("NOT FIXED: Functionality was broken");
        }

        try {
            VerifyFixOutput verifyFixOutput = new VerifyFixOutput();
            verifyFixOutput.setWasExploited(wasExploited);
            verifyFixOutput.setWasBroken(wasBroken);
            String output = Utils.objectToJson(verifyFixOutput);
            System.out.println(output);
        } catch (JAXBException e) {
            System.out.println("ERROR: Could not marshall VerifyFixOutput to JSON");
            e.printStackTrace();
        }

        return !wasExploited && !wasBroken;
    }

    private boolean verifyFixes(
            TestCaseVerificationResultsCollection beforeFixResultsCollection,
            TestCaseVerificationResultsCollection afterFixResultsCollection) {

        boolean isVerified = true;

        // This assumes that the results are ordered.
        if (beforeFixResultsCollection.getResultsObjects().size()
                != afterFixResultsCollection.getResultsObjects().size()) {
            System.out.println("ERROR: Results lists are not the same size");
            isVerified = false;
        } else {
            int count = beforeFixResultsCollection.getResultsObjects().size();
            for (int i = 0; i < count; i++) {
                TestCaseVerificationResults beforeFixResults =
                        beforeFixResultsCollection.getResultsObjects().get(i);
                TestCaseVerificationResults afterFixResults =
                        afterFixResultsCollection.getResultsObjects().get(i);
                isVerified &= verifyFix(beforeFixResults, afterFixResults);
            }
        }
        return isVerified;
    }

    /**
     * Process the command line arguments that make any configuration changes.
     *
     * @param args - args passed to main().
     * @return specified crawler file if valid command line arguments provided. Null otherwise.
     */
    protected void processCommandLineArgs(String[] args) {
        System.out.println("Maven user selected verifyFixed=" + verifyFixed);

        // Set default attack crawler file
        String crawlerFileName = new File(Utils.DATA_DIR, "benchmark-attack-http.xml").getPath();
        this.theCrawlerFile = new File(crawlerFileName);

        RegressionTesting.isTestingEnabled = true;

        // Create the command line parser
        CommandLineParser parser = new DefaultParser();

        HelpFormatter formatter = new HelpFormatter();

        // Create the Options
        Options options = new Options();
        options.addOption(
                Option.builder("b")
                        .longOpt("beforeFixOutputDirectory")
                        .desc("output directory of a previous crawl before fixes")
                        .hasArg()
                        .build());
        options.addOption(
                Option.builder("d")
                        .longOpt("outputDirectory")
                        .desc("output directory")
                        .hasArg()
                        .build());
        options.addOption(
                Option.builder("f")
                        .longOpt("file")
                        .desc("a TESTSUITE-crawler-http.xml file")
                        .hasArg()
                        .required()
                        .build());
        options.addOption(Option.builder("h").longOpt("help").desc("Usage").build());
        options.addOption(
                Option.builder("j")
                        .longOpt("json")
                        .desc("generate json version of verification results")
                        .build());
        //        options.addOption("m", "verifyFixed", false, "verify fixed test suite");
        options.addOption(
                Option.builder("m").longOpt("verifyFixed").desc("verify fixed test suite").build());
        options.addOption(
                Option.builder("n")
                        .longOpt("name")
                        .desc("tescase name (e.g. BenchmarkTestCase00025)")
                        .hasArg()
                        .build());
        options.addOption(
                Option.builder("t")
                        .longOpt("time")
                        .desc("testcase timeout (in seconds)")
                        .hasArg()
                        .type(Integer.class)
                        .build());

        try {
            // Parse the command line arguments
            CommandLine line = parser.parse(options, args);

            if (line.hasOption("b")) {
                beforeFixOutputDirectory = line.getOptionValue("b");
            }
            if (line.hasOption("d")) {
                outputDirectory = line.getOptionValue("d");
            }
            if (line.hasOption("f")) {
                this.crawlerFile = line.getOptionValue("f");
                File targetFile = new File(this.crawlerFile);
                if (targetFile.exists()) {
                    setCrawlerFile(targetFile);
                    // Crawler output files go into the same directory as the crawler config file
                    configurationDirectory = targetFile.getParent();
                } else {
                    throw new RuntimeException(
                            "Could not find crawler configuration file '" + this.crawlerFile + "'");
                }
            }
            if (line.hasOption("h")) {
                formatter.printHelp("BenchmarkCrawlerVerification", options, true);
            }
            if (line.hasOption("j")) {
                generateJSONResults = "true";
            }
            if (line.hasOption("m")) {
                System.out.println("User selected to verify fixes");
                verifyFixed = "true";
            }
            if (line.hasOption("n")) {
                selectedTestCaseName = line.getOptionValue("n");
            }
            if (line.hasOption("t")) {
                maxTimeInSeconds = (Integer) line.getParsedOptionValue("t");
            }
        } catch (ParseException e) {
            formatter.printHelp("BenchmarkCrawlerVerification", options);
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
            if (this.beforeFixOutputDirectory != null) {
                mainArgs.add("-b");
                mainArgs.add(this.beforeFixOutputDirectory);
            }
            if (this.pluginTestCaseNameParam != null) {
                mainArgs.add("-n");
                mainArgs.add(this.pluginTestCaseNameParam);
            }
            if (Boolean.parseBoolean(this.verifyFixed)) {
                // At the command line, only the -m is required, with no value needed
                mainArgs.add("-m");
            }
            if (Boolean.parseBoolean(this.generateJSONResults)) {
                // At the command line, only the -j is required, with no value needed
                mainArgs.add("-j");
            }
            main(mainArgs.stream().toArray(String[]::new));
        }
    }

    public static void main(String[] args) {
        // thisInstance can be set from execute() or here, depending on how this class is invoked
        // (via maven or command line)
        if (thisInstance == null) {
            thisInstance = new BenchmarkCrawlerVerification();
        }
        thisInstance.processCommandLineArgs(args);
        thisInstance.load();
        thisInstance.run();
    }
}
