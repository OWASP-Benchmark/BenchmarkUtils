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

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
    static Map<AbstractTestCaseRequest, String> failedTruePositivesList =
            new LinkedHashMap<AbstractTestCaseRequest, String>();
    static Map<AbstractTestCaseRequest, String> failedFalsePositivesList =
            new LinkedHashMap<AbstractTestCaseRequest, String>();

    // TODO: Make this flag configurable via command line parameter
    private static boolean isVerbosityOn = false;
    private static final String FAILEDTC_FILE = "failedTestCases.txt";

    /** The list of categories that will be included in the regression test. */
    private static final List<String> CATEGORIES_INCLUDED_IN_TEST =
            Arrays.asList(new String[] {"xss", "xxe"});

    public static void genFailedTCFile(
            List<AbstractTestCaseRequest> requests,
            List<ResponseInfo> responseInfoList,
            String dataDir)
            throws IOException {

        int total_tcs = requests.size();
        int verified_xss = 0, verified_xxe = 0, verified_other = 0;
        int tp_pass_xss = 0, tp_fail_xss = 0, fp_pass_xss = 0, fp_fail_xss = 0;
        int tp_pass_xxe = 0, tp_fail_xxe = 0, fp_pass_xxe = 0, fp_fail_xxe = 0;
        int tp_pass_other = 0, tp_fail_other = 0, fp_pass_other = 0, fp_fail_other = 0;

        // TODO: We can skip this loop if we report the sub-totals at the end.
        for (AbstractTestCaseRequest request : requests) {
            if ("xss".equals(request.getCategory())) {
                if (request.isPassed()) {
                    if (request.isVulnerability()) tp_pass_xss++;
                    else fp_pass_xss++;
                } else {
                    if (request.isVulnerability()) tp_fail_xss++;
                    else fp_fail_xss++;
                }
                verified_xss++;
            } else if ("xxe".equals(request.getCategory())) {
                if (request.isPassed()) {
                    if (request.isVulnerability()) tp_pass_xxe++;
                    else fp_pass_xxe++;
                } else {
                    if (request.isVulnerability()) tp_fail_xxe++;
                    else fp_fail_xxe++;
                }
                verified_xxe++;
            } else if (request.getAttackSuccessString() != null) {
                if (request.isPassed()) {
                    if (request.isVulnerability()) tp_pass_other++;
                    else fp_pass_other++;
                } else {
                    if (request.isVulnerability()) tp_fail_other++;
                    else fp_fail_other++;
                }
                verified_other++;
            } // else we can't verify it, so we do nothing.
        }

        System.out.println("\n - Total number of TCs: " + total_tcs + " -- ");
        if (verified_xss > 0) {
            System.out.println(" -- TCs verified in category XSS: " + verified_xss + " -- ");
        }
        if (verified_xxe > 0) {
            System.out.println(" -- TCs verified in category XXE: " + verified_xxe + " -- ");
        }
        if (verified_other > 0) {
            System.out.println(" -- TCs verified in other categories: " + verified_other + " -- ");
        }

        if (tp_fail_xss + fp_fail_xss > 0) {
            // TODO: More refactoring will be needed to support per-category subtotals.
            System.out.println(" ---\t XSS: TP PASSED: " + tp_pass_xss + " -- ");
            System.out.println(" ---\t XSS: FP PASSED: " + fp_pass_xss + " -- ");
            System.out.println(" ---\t XSS: TP FAILED: " + tp_fail_xss + " -- ");
            System.out.println(" ---\t XSS: FP FAILED: " + fp_fail_xss + " -- ");
        }
        if (tp_fail_xxe + fp_fail_xxe > 0) {
            // TODO: More refactoring will be needed to support per-category subtotals.
            System.out.println(" ---\t XXE: TP PASSED: " + tp_pass_xxe + " -- ");
            System.out.println(" ---\t XXE: FP PASSED: " + fp_pass_xxe + " -- ");
            System.out.println(" ---\t XXE: TP FAILED: " + tp_fail_xxe + " -- ");
            System.out.println(" ---\t XXE: FP FAILED: " + fp_fail_xxe + " -- ");
        }
        if (tp_fail_other + fp_fail_other > 0) {
            // TODO: More refactoring will be needed to support per-category subtotals.
            System.out.println(" ---\t Other: TP PASSED: " + tp_pass_other + " -- ");
            System.out.println(" ---\t Other: FP PASSED: " + fp_pass_other + " -- ");
            System.out.println(" ---\t Other: TP FAILED: " + tp_fail_other + " -- ");
            System.out.println(" ---\t Other: FP FAILED: " + fp_fail_other + " -- ");
        }
        if (tp_fail_xss + fp_fail_xss + tp_fail_xxe + fp_fail_xxe + tp_fail_other + fp_fail_other
                > 0) {
            List<String> failedInformation = new ArrayList<String>();
            int count = 0;
            for (AbstractTestCaseRequest request : requests) {
                ResponseInfo rInfo = responseInfoList.get(count++);
                if (isIncludedInTest(request)) {
                    if (isVerbosityOn) {
                        System.out.println("");
                        System.out.println(
                                request.getName()
                                        + " category: "
                                        + request.getCategory()
                                        + " isVulnerability?: "
                                        + request.isVulnerability()
                                        + "   isPassed?:"
                                        + request.isPassed());
                        System.out.println(request.getFullURL());
                    }

                    if (!request.isPassed()) {
                        System.out.println(
                                "FAILURE: "
                                        + request.isVulnerability()
                                        + " positive "
                                        + request.getCategory()
                                        + " test case failed: "
                                        + request.getName());
                        failedInformation.add(
                                "Failed "
                                        + request.isVulnerability()
                                        + " positive "
                                        + request.getCategory()
                                        + " Test Case Request "
                                        + request.getName()
                                        + ":");
                        failedInformation.add(request.toString());
                        failedInformation.add("");
                        failedInformation.add("Response:");
                        failedInformation.add(rInfo.getResponseString());
                        failedInformation.add("");
                        failedInformation.add(
                                "Attack success indicator: -->"
                                        + request.getAttackSuccessString()
                                        + "<--");
                        failedInformation.add("");
                    }
                }
            }
            final String PATHTOFAILEDTC_FILE = dataDir + FAILEDTC_FILE;
            Path outputFile = Paths.get(PATHTOFAILEDTC_FILE);
            Utils.writeToFile(outputFile, failedInformation, false);
            System.out.println("Details of failed test cases written to: " + PATHTOFAILEDTC_FILE);
        }
        System.out.println(
                " -- Summary: TCs PASSED: "
                        + (tp_pass_xss
                                + fp_pass_xss
                                + tp_pass_xxe
                                + fp_pass_xxe
                                + tp_pass_other
                                + fp_pass_other)
                        + " -- ");
        System.out.println(
                " -- Summary: TCs FAILED: "
                        + (tp_fail_xss
                                + fp_fail_xss
                                + tp_fail_xxe
                                + fp_fail_xxe
                                + tp_fail_other
                                + fp_fail_other)
                        + " -- ");
        System.out.println(
                " -- Number of TCs not yet verifiable: "
                        + (total_tcs - verified_xss - verified_xxe - verified_other)
                        + " -- ");
    }

    /**
     * Method to verify if the provided payload was included in the response, or the status code
     * wasn't a 200.
     *
     * @param testCaseRequest - The TestCaseRequest for this test case.
     * @param response - The response from this test case.
     * @param payload - The payload to look for in the response to determine if the attack was
     *     successful.
     * @param statusCode - The status code from the response. Anything but 200 is considered a test
     *     case failure.
     *     <p>Has the following side effects: testCaseRequest.setPassed() - If test is verifiable,
     *     and payload not found in response, set to false, otherwise true. Set to true for all
     *     non-verifiable True Positives.
     */
    public static void verifyTestCase(
            AbstractTestCaseRequest testCaseRequest,
            String response,
            String payload,
            int statusCode) {

        payload = payload.replace("REFERER", ""); // Rip out any REFERER values

        if (testCaseRequest.isVulnerability()) {
            if (response.contains(payload)) {
                testCaseRequest.setPassed(true);
            } else {
                testCaseRequest.setPassed(false);
            }
        } // Verify the XSS false positives are NOT exploitable
        else if (response.contains(payload)) {
            testCaseRequest.setPassed(false);
        } else {
            testCaseRequest.setPassed(true);
        }

        String reason = "";
        boolean testCaseFailed = false;

        if (statusCode != 200) {
            reason += "\t- Response code: " + statusCode + " ";
            testCaseFailed = true;
        }

        if (response.toLowerCase().contains("exception")) {
            if (testCaseFailed) reason += "/ Response contains: exception ";
            else reason += "\t- Response contains: exception ";
            testCaseFailed = true;
        } else if (response.toLowerCase().contains("error")) {
            if (testCaseFailed) reason += "/ Response contains: error ";
            else reason += "\t- Response contains: error ";
            testCaseFailed = true;
        }

        if (testCaseRequest.isVulnerability()) {
            truePositives++;
            if (testCaseFailed) {
                failedTruePositives++;
                failedTruePositivesList.put(testCaseRequest, reason);
            }
        } else {
            falsePositives++;
            if (testCaseFailed) {
                failedFalsePositives++;
                failedFalsePositivesList.put(testCaseRequest, reason);
            }
        }
    }

    private static boolean isIncludedInTest(AbstractTestCaseRequest testCaseRequest) {
        return CATEGORIES_INCLUDED_IN_TEST.contains(testCaseRequest.getCategory())
                || (testCaseRequest.getAttackSuccessString() != null);
    }
}
