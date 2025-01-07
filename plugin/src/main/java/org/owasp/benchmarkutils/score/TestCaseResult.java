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
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmarkutils.score;

import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.Category;
import org.owasp.benchmarkutils.helpers.CategoryGroup;
import org.owasp.benchmarkutils.helpers.CategoryGroups;
import org.owasp.benchmarkutils.score.parsers.Reader;
import org.owasp.benchmarkutils.score.service.ExpectedResultsProvider;
import org.owasp.benchmarkutils.tools.AbstractTestCaseRequest;

/* This class represents a single test case result. It documents the expected result (real),
 * and the actual result (result).
 */

public class TestCaseResult {

    public static final String UNMAPPED_CATEGORY = "unmappedCWECategory";
    private static final String TEST_ID_PAD_INT_wZEROS = "%0" + BenchmarkScore.TESTIDLENGTH + "d";

    private String testCaseName = ""; // The name of the test case (E.g., BenchmarkTest00001)
    // testID is the unique ID for this test case. For Benchmark Style, its a number (e.g., 1), for
    // nonBenchmark Style its the name of the entire test case (e.g., FooBar_TryThis02).
    private String testID = "0";
    private boolean truePositive = false; // Is this test case a true or false positive?
    private boolean result = false; // Did a tool properly detect this as a true or false positive?
    private int CWE = 0;
    private String category = null; // pathtraver, hash, cmdi, etc.
    private CategoryGroup categoryGroup =
            null; // Optional field used to group CWEs into groups of CWEs
    private String evidence = null;
    private int confidence = 0;

    // optional attributes
    private String source = null;
    private String dataflow = null;
    private String sink = null;

    // Used to store the details of how an actual tool matched (or did not match) against an
    // expected TestCaseResult
    private CweMatchDetails cweMatch = null;

    // This is a special 'magic' testcase number which indicates we aren't using test case numbers
    // for this particular scoring
    public static final int NOT_USING_TESTCASE_NUMBERS = -654321;

    public TestCaseResult() {
        // By default, do nothing special.
    }

    /**
     * Convert what we know about a TestCase Request description back into a TestCaseResult
     * (expected or actual)
     *
     * @param request The request object used to access this test case.
     */
    public TestCaseResult(AbstractTestCaseRequest request) {
        this.testCaseName = request.getName();
        this.truePositive = request.isVulnerability();
        this.CWE = request.getCategory().getCWE();
        this.category = Categories.getCategoryByCWE(this.CWE).getName();

        // fill in optional attributes since we have this data available
        this.source = request.getSourceFile();
        this.dataflow = request.getDataflowFile();
        this.sink = request.getSinkFile();
    }

    /**
     * Set the name of the test case (E.g., BenchmarkTest00001). This is frequently only used for
     * expected results, not actual results. Expected to actual can be correlated by the test
     * number.
     *
     * @name The name of the test case
     */
    public void setTestCaseName(String name) {
        this.testCaseName = name;
    }

    /**
     * Get the name of the test case. E.g., BenchmarkTest00001
     *
     * @return The test case name
     */
    public String getTestCaseName() {
        return this.testCaseName;
    }

    public int getConfidence() {
        return this.confidence;
    }

    public void setConfidence(int confidence) {
        this.confidence = confidence;
    }

    /**
     * Return the unique testID for this test case. For Benchmark Style, its a number (e.g., 00001),
     * for nonBenchmark Style its the name of the entire test case (e.g., FooBar_TryThis02).
     *
     * @return The testID for this test case.
     */
    public String getTestID() {
        return this.testID;
    }

    /**
     * Sets the unique identifier for this test case. For Benchmark style scoring, its the test ID
     * number, converted to a String. For nonBenchmark Style its the name of the entire test case
     * (e.g., FooBar_TryThis02)
     *
     * <p>Deprecated: The use of this method should be converted to use setActualResultTestID() for
     * tool parsers.
     *
     * @param id The unique test case number for this Benchmark style test case.
     */
    @Deprecated
    public void setTestID(int id) {
        this.testID = String.format(TestCaseResult.TEST_ID_PAD_INT_wZEROS, id);
    }

    /**
     * Sets the unique identifier for this test case. For Benchmark style, it parses out the test
     * case number and uses that as the test ID. For non-Benchmark style scoring, it used the name
     * of the tool result file to try to find the matching expected result test case name. In this
     * case, if the reported filename from the tool starts with the name of a test case, then the
     * test case name, is used as the testID. That way if there are multi-file test cases that all
     * start with the same name, they will all match up against the expected result name with that
     * name.
     *
     * @param testCaseFileName The test case file name, without path information.
     */
    public void setActualResultTestID(String testCaseFileName) {
        if (ExpectedResultsProvider.isBenchmarkStyleScoring()) {
            // Sets the test ID to the test case # or -1 if not a match
            // We format the int with leading zeros so it will sort the results array properly when
            // its converted to a String
            this.testID =
                    String.format(
                            TestCaseResult.TEST_ID_PAD_INT_wZEROS,
                            Reader.getBenchmarkStyleTestCaseNumber(testCaseFileName.trim()));
        } else {
            if (testCaseFileName.contains("/") || testCaseFileName.contains("\\")) {
                new IllegalArgumentException(
                                "FATAL ERROR: testCaseFileName value: "
                                        + testCaseFileName
                                        + " passed to setActualResultTestID() can't have any path information")
                        .printStackTrace();
                System.exit(-1);
            }
            // For actual results, we look for a matching test case name, and set that as the testID
            String matchingID =
                    ExpectedResultsProvider.getExpectedResults()
                            .getMatchingTestCaseName(testCaseFileName);
            if (matchingID == null) {
                new IllegalArgumentException(
                                "FATAL ERROR: testCaseFileName value: "
                                        + testCaseFileName
                                        + " passed to setActualResultTestID() doesn't match any expected results test case name.")
                        .printStackTrace();
                System.exit(-1);
            }
            this.testID = matchingID;
        }
    }

    /**
     * Sets the unique identifier for this test case. For non-Benchmark style scoring, its the name
     * of the test case. For Benchmark style, it parses out the test case number and uses that as
     * the test ID, padding with leading zeroes.
     *
     * @param id The test case file name, without path information.
     */
    public void setExpectedResultTestID(String testCaseFileName) {
        if (ExpectedResultsProvider.isBenchmarkStyleScoring()) {
            // Sets the test ID to the test case # or -1 if not a match
            this.testID =
                    String.format(
                            TestCaseResult.TEST_ID_PAD_INT_wZEROS,
                            Reader.getBenchmarkStyleTestCaseNumber(testCaseFileName.trim()));
        } else {
            if (testCaseFileName.contains("/") || testCaseFileName.contains("\\")) {
                new IllegalArgumentException(
                                "FATAL ERROR: testCaseFileName value: "
                                        + testCaseFileName
                                        + " passed to setExpectedResultTestID() can't have any path information")
                        .printStackTrace();
                System.exit(-1);
            }
            // For expected results, we don't change the test case file name
            this.testID = testCaseFileName.trim();
        }
    }

    public boolean isTruePositive() {
        return this.truePositive;
    }

    public void setTruePositive(boolean truePositive) {
        this.truePositive = truePositive;
    }

    public boolean isPassed() {
        return this.result;
    }

    public void setPassed(boolean result) {
        this.result = result;
    }

    public int getCWE() {
        return this.CWE;
    }

    public void setCWE(int cwe) {
        this.CWE = cwe;
        Category category = Categories.getCategoryByCWE(cwe);
        if (category != null) {
            this.category = category.getId();
        } else {
            this.category = TestCaseResult.UNMAPPED_CATEGORY;
        }
    }

    /**
     * If CategoryGroups have been defined, this looks up the group this CWE belongs to and sets the
     * Group for this test case. If there is no mapping for this CWE # to a Group, this is a fatal
     * error. This should ONLY be called for Expected Results, not actual results.
     *
     * @param cwe The CWE to map to a Category Group
     */
    public void setCategoryGroup(int cwe) {
        if (CategoryGroups.isCategoryGroupsEnabled()) {
            this.categoryGroup = CategoryGroups.getCategoryGroupByCWE(cwe);
        }
    }

    /**
     * Returns the CategoryGroup this test case result has been mapped to, or null if not set.
     *
     * @return Its CategoryGroup
     */
    public CategoryGroup getCategoryGroup() {
        return this.categoryGroup;
    }

    /**
     * This method is used to abstract away how filenames are matched against a test case, that way
     * it can be enhanced to support different test suite formats, and the logic on how to do this
     * isn't implemented in every individual parser. This method expects that
     * ExpectedResultsProvider.getExpectedResults().isTestCaseFile(filename) was called first to
     * verify this file is a test case in the test suite being scored. It sets the CWE number and
     * the test case name in this TestCaseResult if successful. It halts with an error if the
     * supplied filename is not a valid test case.
     *
     * @param cwe The CWE # reported by this tool.
     * @param filename The filename that might be a test case.
     */
    public void setCWEAndTestCaseID(int cwe, String filename) {
        if (ExpectedResultsProvider.getExpectedResults().isTestCaseFile(filename)) {
            // DRW TODO
        }
    }

    /**
     * The CWE category name, e.g., pathtraver, hash, cmdi, etc.
     *
     * @return The descriptive name of this CWE, per categories.xml
     */
    public String getCategory() {
        return this.category;
    }

    public String getEvidence() {
        return this.evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getSource() {
        return this.source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getDataFlow() {
        return this.dataflow;
    }

    public void setDataFlow(String dataflow) {
        this.dataflow = dataflow;
    }

    public String getSink() {
        return this.sink;
    }

    public void setSink(String sink) {
        this.sink = sink;
    }

    /**
     * This method is ONLY used for capturing the details of actual results against an expected
     * result. As such, this should only be used on an expected TestCaseResult.
     *
     * @param cweMatch The CweMatch details for a tool against this expected result
     */
    public void addMatchDetails(CweMatchDetails cweMatch) {
        this.cweMatch = cweMatch;
    }

    /**
     * This method is ONLY used for retrieving the details of actual results against an expected
     * result. As such, this should only be used on an expected TestCaseResult.
     *
     * @return The CweMatch details for a tool against this expected result. Null if not yet set.
     */
    public CweMatchDetails getMatchDetails() {
        return this.cweMatch;
    }

    @Override
    public String toString() {
        return "Testcase ID: "
                + getTestID()
                + ", Category: "
                + getCategory()
                + ", isVulnerable: "
                + isTruePositive()
                + ", CWE: "
                + getCWE()
                + ", toolPassed: "
                + isPassed();
        /*                + ", evidence: "
                        + getEvidence()
                        + ", confidence: "
                        + getConfidence();
        */ }
}
