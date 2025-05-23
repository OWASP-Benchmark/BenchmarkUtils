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

import com.google.common.collect.Multiset;
import com.google.common.collect.SortedMultiset;
import com.google.common.collect.TreeMultiset;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.xml.bind.JAXBException;
import org.apache.commons.io.IOUtils;
import org.apache.hc.client5.http.classic.methods.HttpPost;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.HttpMessage;
import org.owasp.benchmarkutils.entities.CliResponseInfo;
import org.owasp.benchmarkutils.entities.HttpResponseInfo;
import org.owasp.benchmarkutils.entities.HttpTestCaseInput;
import org.owasp.benchmarkutils.entities.ResponseInfo;
import org.owasp.benchmarkutils.entities.TestCase;
import org.owasp.benchmarkutils.helpers.Utils;

/**
 * Test all supported test cases to verify that the results are as expected and write the report to
 * a file.
 */
public class RegressionTesting {

    // Directly accessed by multiple classes, and set by some too
    public static boolean isTestingEnabled = false;

    // These are accessed by BenchmarkCrawlerVerification
    static int truePositives = 0;
    static int falsePositives = 0;
    static int failedTruePositives = 0;
    static int failedFalsePositives = 0;

    static int totalCount = 0;
    static int truePositivePassedCount = 0;
    static int falsePositivePassedCount = 0;
    static int truePositiveFailedCount = 0;
    static int falsePositiveFailedCount = 0;
    static int verifiedCount = 0;
    static int declaredUnverifiable = 0;
    static int undeclaredUnverifiable = 0;

    static SortedMultiset<String> undeclaredUnverifiableSinks = TreeMultiset.create();
    static SortedMultiset<String> nonDiscriminatorySinks = TreeMultiset.create();
    static SortedMultiset<String> failSinks = TreeMultiset.create();

    static Map<TestCase, String> failedTruePositivesList = new LinkedHashMap<>();
    static Map<TestCase, String> failedFalsePositivesList = new LinkedHashMap<>();

    // TODO: Make this flag configurable via command line parameter
    private static boolean isVerbosityOn = false;
    private static final String FILENAME_FAILEDTC = "failedTestCases.txt";
    private static final String FILENAME_TC_VERIF_RESULTS_JSON = "testCaseVerificationResults.json";

    /** The list of categories that will be included in the regression test. */
    private static final List<String> CATEGORIES_INCLUDED_IN_TEST =
            Arrays.asList(new String[] {"xss", "xxe"});

    // TODO: Since these logs are static, we might only be able to use (close) it once.
    static SimpleFileLogger tcJsonLogger;
    static SimpleFileLogger ftcLogger;

    /**
     * Write a log file containing the verification results of all test cases, as JSON.
     *
     * @param results The verification results to log
     * @param dataDir The directory to write the logfile to
     * @param generate If true, generate log file, otherwise skip
     * @throws IOException
     * @throws LoggerConfigurationException
     */
    public static void genAllTCResultsToJsonFile(
            TestCaseVerificationResultsCollection resultsCollection,
            String dataDir,
            boolean generate)
            throws IOException, LoggerConfigurationException {

        if (generate) {

            final File FILE_TC_VERIF_RESULTS_JSON =
                    new File(dataDir, FILENAME_TC_VERIF_RESULTS_JSON);
            SimpleFileLogger.setFile("TC_VERIF_RESULTS_JSON", FILE_TC_VERIF_RESULTS_JSON);

            try (SimpleFileLogger tcJSON = SimpleFileLogger.getLogger("TC_VERIF_RESULTS_JSON")) {

                tcJsonLogger = tcJSON;

                // Create JSON version of verification results for ALL test cases
                tcJsonLogger.println(Utils.objectToJson(resultsCollection));
            } catch (JAXBException e) {
                System.out.println("Fatal Error trying to convert verification results to JSON");
                e.printStackTrace();
                System.exit(-1);
            }
        }
    }

    /**
     * Write a log file containing the details of all failed test cases.
     *
     * @param results
     * @param dataDir
     * @throws IOException
     * @throws LoggerConfigurationException
     */
    public static void genFailedTCFile(List<TestCaseVerificationResults> results, String dataDir)
            throws IOException, LoggerConfigurationException {

        final File FILE_FAILEDTC = new File(dataDir, FILENAME_FAILEDTC);
        SimpleFileLogger.setFile("FAILEDTC", FILE_FAILEDTC);

        try (SimpleFileLogger ftc = SimpleFileLogger.getLogger("FAILEDTC")) {

            ftcLogger = ftc;

            totalCount = results.size();

            for (TestCaseVerificationResults result : results) {
                //                AbstractTestCaseRequest requestTemplate =
                // result.getRequestTemplate();
                TestCase testCase = result.getTestCase();

                String sink = null;
                String sinkMetaDataFilePath = testCase.getSinkFile();
                if (sinkMetaDataFilePath != null) {
                    String sinkMetaDataFilename = new File(sinkMetaDataFilePath).getName();
                    sink = sinkMetaDataFilename.substring(0, sinkMetaDataFilename.indexOf('.'));
                }

                if (result.isUnverifiable()) {
                    if (result.isDeclaredUnverifiable()) {
                        declaredUnverifiable++;
                    } else {
                        undeclaredUnverifiable++;
                        if (sink == null) {
                            System.out.printf(
                                    "ERROR: No sink for request %s%n", testCase.getName());
                        } else {
                            undeclaredUnverifiableSinks.add(sink);
                        }
                    }
                } else {
                    if (result.isPassed()) {
                        if (testCase.isVulnerability()) truePositivePassedCount++;
                        else falsePositivePassedCount++;
                    } else {
                        if (testCase.isVulnerability()) truePositiveFailedCount++;
                        else falsePositiveFailedCount++;
                    }
                    verifiedCount++;
                }
            }

            if (truePositiveFailedCount + falsePositiveFailedCount > 0) {
                for (TestCaseVerificationResults result : results) {
                    TestCase testCase = result.getTestCase();
                    if (isIncludedInTest(testCase)) {
                        if (isVerbosityOn) {
                            System.out.println();
                            System.out.printf(
                                    "Test case request %s (category: %s, isVulnerability: %b, isNonverifiable: %b, isPassed: %b)%n",
                                    testCase.getName(),
                                    testCase.getCategory().toString(),
                                    testCase.isVulnerability(),
                                    result.isUnverifiable(),
                                    result.isPassed());
                            HttpTestCaseInput httpTestCaseInput =
                                    (HttpTestCaseInput) testCase.getTestCaseInput();
                            System.out.println(httpTestCaseInput.getUrl());
                        }

                        if (!result.isUnverifiable()) {
                            if (result.isPassed()) {
                                testCase.setVerificationResult("VERIFIED");
                            } else {
                                testCase.setVerificationResult("FAILURE");
                                System.out.printf(
                                        "FAILURE: %s positive %s test case request %s%n",
                                        testCase.isVulnerability() ? "True" : "False",
                                        testCase.getCategory().toString(),
                                        testCase.getName());
                            }
                        }
                    }
                }
            }

            if (truePositiveFailedCount + falsePositiveFailedCount > 0) {
                for (TestCaseVerificationResults result : results) {
                    TestCase testCase = result.getTestCase();
                    if (isIncludedInTest(testCase)) {
                        if (!result.isUnverifiable() && !result.isPassed()) {
                            ftcLogger.print("FAILURE: ");
                            printTestCaseDetailsAsText(result, ftcLogger);
                        }
                    }
                }
                if (FILE_FAILEDTC.length() > 0) {
                    System.out.printf(
                            "Details of failed test cases written to: %s%n", FILE_FAILEDTC);
                }
            }
        }
    }

    private static void printHttpRequest(HttpMessage request, Logger out) {
        out.println(request.toString());
        for (Header header : request.getHeaders()) {
            out.printf("%s:%s%n", header.getName(), header.getValue());
        }
        if (request instanceof HttpPost) {
            HttpPost postHttpRequest = (HttpPost) request;
            out.println();
            try {
                HttpEntity entity = postHttpRequest.getEntity();
                if (entity != null) {
                    out.println(IOUtils.toString(entity.getContent(), StandardCharsets.UTF_8));
                }
            } catch (IOException e) {
                System.out.println("ERROR: Could not parse HttpPost entities");
                e.printStackTrace();
            }
        }
    }

    private static void printTestCaseDetailsAsText(TestCaseVerificationResults result, Logger out) {

        TestCase testCase = result.getTestCase();
        ResponseInfo attackResponseInfo = result.getResponseToAttackValue();
        ResponseInfo safeResponseInfo = result.getResponseToSafeValue();
        out.printf(
                "%s positive %s test case request %s%n",
                testCase.isVulnerability() ? "True" : "False",
                testCase.getCategory().toString(),
                testCase.getName());
        // Print out all attributes of the request, including the templates used to create it
        out.println(testCase.toString());
        out.println();
        out.println("Attack request:");
        out.println(result.getAttackTestExecutorDescription());
        if (attackResponseInfo instanceof HttpResponseInfo) {
            out.printf(
                    "Attack response: [%d]:%n",
                    ((HttpResponseInfo) attackResponseInfo).getStatusCode());
            out.println(
                    attackResponseInfo == null
                            ? "null"
                            : ((HttpResponseInfo) attackResponseInfo).getResponseString());
        } else if (attackResponseInfo instanceof CliResponseInfo) {
            out.printf(
                    "Attack response: [%d]:%n",
                    ((CliResponseInfo) attackResponseInfo).getStatusCode());
            out.println(
                    attackResponseInfo == null
                            ? "null"
                            : ((CliResponseInfo) attackResponseInfo).getResponseString());
        }
        out.println();
        out.println("Safe request:");
        out.println(result.getSafeTestExecutorDescription());
        if (safeResponseInfo instanceof HttpResponseInfo) {
            out.printf(
                    "Safe response: [%d]:%n",
                    ((HttpResponseInfo) safeResponseInfo).getStatusCode());
            out.println(
                    safeResponseInfo == null
                            ? "null"
                            : ((HttpResponseInfo) safeResponseInfo).getResponseString());
        } else if (safeResponseInfo instanceof CliResponseInfo) {
            out.printf(
                    "Safe response: [%d]:%n", ((CliResponseInfo) safeResponseInfo).getStatusCode());
            out.println(
                    safeResponseInfo == null
                            ? "null"
                            : ((CliResponseInfo) safeResponseInfo).getResponseString());
        }
        out.println();
        out.printf("Attack success indicator: -->%s<--%n", testCase.getAttackSuccessString());
        out.printf("-----------------------------------------------------------%n%n");
    }

    /**
     * Print to the console a summary of the last crawl.
     *
     * @param results
     * @throws LoggerConfigurationException
     * @throws FileNotFoundException
     */
    public static void printCrawlSummary(List<TestCaseVerificationResults> results)
            throws FileNotFoundException, LoggerConfigurationException {

        int unverifiedCount = declaredUnverifiable + undeclaredUnverifiable;
        System.out.println("\n - Total number of test cases: " + totalCount);
        if (declaredUnverifiable > 0) {
            System.out.printf(" -- Declared not auto-verifiable: %d%n", declaredUnverifiable);
        }

        System.out.printf(
                " -- Test cases PASSED: %d%n", truePositivePassedCount + falsePositivePassedCount);
        System.out.printf("\tTP PASSED: %d%n", truePositivePassedCount);
        System.out.printf("\tFP PASSED: %d%n", falsePositivePassedCount);
        System.out.println(" - Problems:");
        System.out.printf(
                " -- Test cases FAILED: %d%n", truePositiveFailedCount + falsePositiveFailedCount);
        System.out.printf("\tTP FAILED: %d%n", truePositiveFailedCount);
        System.out.printf("\tFP FAILED: %d%n", falsePositiveFailedCount);
        if (failSinks.size() > 0) {
            System.out.printf(" -- Failed test cases by sink (total: %d)%n", failSinks.size());
            for (Multiset.Entry<String> sinkEntry : failSinks.entrySet()) {
                System.out.printf("\t%s (%d)%n", sinkEntry.getElement(), sinkEntry.getCount());
            }
        }

        if (undeclaredUnverifiableSinks.size() > 0) {
            System.out.printf(
                    " -- Unverifiable test cases by sink (total: %d)%n", undeclaredUnverifiable);
            System.out.println(
                    " (These sink .xml files are missing both the <attack-success-indicator> and <not-autoverifiable> attributes.)");
            for (Multiset.Entry<String> sinkEntry : undeclaredUnverifiableSinks.entrySet()) {
                System.out.printf("\t%s (%d)%n", sinkEntry.getElement(), sinkEntry.getCount());
            }
        }

        if (nonDiscriminatorySinks.size() > 0) {
            System.out.printf(
                    " -- Non-discriminatory test cases by sink (total: %d)%n",
                    nonDiscriminatorySinks.size());
            for (Multiset.Entry<String> sinkEntry : nonDiscriminatorySinks.entrySet()) {
                System.out.printf("\t%s (%d)%n", sinkEntry.getElement(), sinkEntry.getCount());
            }
        }

        if (totalCount - verifiedCount != unverifiedCount) {
            System.out.printf(
                    "ERROR: Unverifiable (%d) count does not equal total count minus verified count (%d - %d = %d)%n",
                    unverifiedCount, totalCount, verifiedCount, totalCount - verifiedCount);
        }
    }

    /**
     * Method to verify if the provided attackSuccessIndicator was included in the response, or the
     * status code wasn't a 200.
     *
     * <p>Has the following side effects: testCaseRequest.setPassed() - If test is verifiable, and
     * attackSuccessIndicator not found in response, setPassed set to false, otherwise true. Set to
     * true for all non-verifiable True Positives.
     * <!-- spotless:off -->
     *	If vulnerability
     * 		If attackValue response is verified and safeValue response is not verified --> pass
     *		If attackValue response is verified and safeValue response is verified --> fail and not
     *			discriminatory
     *		If attackValue response is not verified --> fail
	 *	Else
     *   	If attackValue response is not verified and safeValue response is not verified --> pass
     *   	If attackValue response is not verified and safeValue response is verified --> fail and
     *   		not discriminatory
     *   	If attackValue response is verified --> fail
	 * <!-- spotless:on -->
     *
     * @param result - The TestCaseVerificationResults for this test case.
     * @throws FileNotFoundException
     * @throws LoggerConfigurationException
     */
    public static void verifyTestCase(TestCaseVerificationResults result)
            throws FileNotFoundException, LoggerConfigurationException {

        SimpleFileLogger ndLogger = SimpleFileLogger.getLogger("NONDISCRIMINATORY");
        SimpleFileLogger uLogger = SimpleFileLogger.getLogger("UNVERIFIABLE");

        result.setUnverifiable(false); // Default
        result.setDeclaredUnverifiable(false); // Default
        TestCase testCase = result.getTestCase();
        if (testCase.isUnverifiable()) {
            // Count this as "declared unverifiable" and return
            result.setUnverifiable(true);
            result.setDeclaredUnverifiable(true);
        } else if (testCase.getAttackSuccessString() == null) {
            // Count this as "undeclared unverifiable" and return
            result.setUnverifiable(true);
            result.setDeclaredUnverifiable(false);
            uLogger.print("UNVERIFIABLE: ");
            printTestCaseDetailsAsText(result, uLogger);
        }

        List<String> reasons = new ArrayList<>();

        String sink = null;
        String sinkMetaDataFilePath = testCase.getSinkFile();
        if (sinkMetaDataFilePath != null) {
            String sinkMetaDataFilename = new File(sinkMetaDataFilePath).getName();
            sink = sinkMetaDataFilename.substring(0, sinkMetaDataFilename.indexOf('.'));
        }

        if (!result.isUnverifiable()) {
            boolean isAttackValueVerified =
                    verifyResponse(
                            result.getResponseToAttackValue().getResponseString(),
                            testCase.getAttackSuccessString());
            boolean isSafeValueVerified =
                    verifyResponse(
                            result.getResponseToSafeValue().getResponseString(),
                            testCase.getAttackSuccessString());
            if (testCase.isVulnerability()) {
                // True positive success?
                if (isAttackValueVerified) {
                    result.setPassed(true);
                    if (isSafeValueVerified) {
                        ndLogger.printf(
                                "Non-discriminatory true positive test %s: The attack-success-string: \"%s\" was found in the response to both the safe and attack requests.%n"
                                        + "\tTo verify that a test case is a true positive, the attack-success-string should be in the attack response, and not%n\tthe safe response. Please change the attack-success-string and/or the test case sink itself to ensure that the%n\tattack-success-string response is present only in a response to a successful attack.%n",
                                testCase.getName(), testCase.getAttackSuccessString());
                        printTestCaseDetailsAsText(result, ndLogger);
                        nonDiscriminatorySinks.add(sink);
                    }
                } else {
                    result.setPassed(false);
                    failSinks.add(sink);
                }
            } else {
                // False positive success?
                if (isAttackValueVerified) {
                    result.setPassed(false);
                    failSinks.add(sink);
                } else {
                    result.setPassed(true);
                    if (isSafeValueVerified) {
                        ndLogger.printf(
                                "Non-discriminatory false positive test %s: The attack-success-string: \"%s\" was found in the response to the safe request.%n"
                                        + "\tTo verify that a test case is a false positive, the attack-success-string should not be in any response to this test%n\tcase. Please change the attack-success-string and/or the test case sink itself to ensure that the%n\tattack-success-string response is present only in a response to a successful attack.%n",
                                testCase.getName(), testCase.getAttackSuccessString());
                        printTestCaseDetailsAsText(result, ndLogger);
                        nonDiscriminatorySinks.add(sink);
                    }
                }
            }
        }

        reasons = findErrors(result);
        boolean hasErrors = reasons.size() > 0;

        String compositeReason = "\t- " + String.join(", ", reasons);

        if (testCase.isVulnerability()) {
            truePositives++;
            if (hasErrors) {
                failedTruePositives++;
                failedTruePositivesList.put(testCase, compositeReason);
            }
        } else {
            falsePositives++;
            if (hasErrors) {
                failedFalsePositives++;
                failedFalsePositivesList.put(testCase, compositeReason);
            }
        }
    }

    private static List<String> findErrors(TestCaseVerificationResults result) {
        List<String> reasons = new ArrayList<>();

        reasons.addAll(findErrors(result.getResponseToAttackValue(), "Attack value"));
        reasons.addAll(findErrors(result.getResponseToSafeValue(), "Safe value"));

        return reasons;
    }

    private static List<String> findErrors(ResponseInfo responseInfo, String prefix) {
        List<String> reasons = new ArrayList<>();

        if (responseInfo != null) {
            if (responseInfo instanceof HttpResponseInfo) {
                int statusCode = ((HttpResponseInfo) responseInfo).getStatusCode();
                if (statusCode != 200) {
                    reasons.add(prefix + " response code: " + statusCode);
                }
            } else if (responseInfo instanceof CliResponseInfo) {
                int returnCode = ((CliResponseInfo) responseInfo).getStatusCode();
                if (returnCode != 0) {
                    reasons.add(prefix + " response code: " + returnCode);
                }
            }
            if (responseInfo.getResponseString().toLowerCase().contains("error")) {
                reasons.add(prefix + " response contains: error");
            } else if (responseInfo.getResponseString().toLowerCase().contains("exception")) {
                reasons.add(prefix + " response contains: exception");
            }
        }

        return reasons;
    }

    /**
     * Method to verify if the provided payload was included in the response.
     *
     * @param response - The response from this test case.
     * @param attackSuccessIndicator - The value to look for in the response to determine if the
     *     attack was successful.
     * @return true if the response passes the described checks. False otherwise.
     */
    public static boolean verifyResponse(String response, String attackSuccessIndicator) {

        // Rip out any REFERER values
        attackSuccessIndicator = attackSuccessIndicator.replace("REFERER", "");

        return response.contains(attackSuccessIndicator);
    }

    private static boolean isIncludedInTest(TestCase testCase) {
        return CATEGORIES_INCLUDED_IN_TEST.contains(testCase.getCategory().getId())
                || (testCase.getAttackSuccessString() != null);
    }
}
