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

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.owasp.benchmarkutils.score.service.ExpectedResultsProvider;

/**
 * TestSuiteResults contains the expected results for each test case in a test suite, if its
 * initialized with the expected results file. Or the actual results for a single tool against each
 * test case in test suite.
 */
public class TestSuiteResults {

    // The types of tools that can generate results
    public static enum ToolType {
        SAST,
        DAST,
        IAST,
        Hybrid
    }

    // The -1 is so we warn (currently) when there is over 10,000 test cases, not 100,000
    private static final int MAX_TEST_CASE_WARNING_NUMBER =
            (int) Math.pow(10, BenchmarkScore.TESTIDLENGTH - 1);

    private static int nextCommercialSAST_ToolNumber = 1;
    private static int nextCommercialDAST_ToolNumber = 1;
    private static int nextCommercialIAST_ToolNumber = 1;
    private static int nextCommercialHybrid_ToolNumber = 1;

    // The name and version of the test suite these test results are for
    private String testSuiteName = "notSet";
    private String testSuiteVersion = "notSet";

    private String toolName = "Unknown Tool";
    private String toolVersion = null;
    private String scanTime = "Unknown"; // Scan time. e.g., '0:17:29'
    public final boolean isCommercial;
    public final ToolType toolType;
    // Map of test case IDs to all the results for that particular test case
    private Map<String, List<TestCaseResult>> testCaseResults =
            new TreeMap<String, List<TestCaseResult>>();

    // Used to track if this tool has been anonymized
    private boolean anonymous = false;

    public TestSuiteResults(String toolname, boolean isCommercial, ToolType toolType) {
        if (toolname == null) {
            System.err.println("ERROR: TestSuiteResults being created without toolname.");
        }
        this.setTool(toolname);
        this.isCommercial = isCommercial;
        if (toolType == null && !"Expected".equals(toolname)) {
            System.out.println(
                    "ERROR: TestSuiteResults being created for tool: "
                            + toolname
                            + " with toolType = null");
        }
        this.toolType = toolType;
    }

    // Set the test suite name for this specific set of TestResults
    public void setTestSuiteName(String name) {
        this.testSuiteName = name;
    }

    public String getTestSuiteName() {
        return this.testSuiteName;
    }

    // Set the version number for this specific set of TestResults
    public void setTestSuiteVersion(String version) {
        this.testSuiteVersion = version;
    }

    public String getTestSuiteVersion() {
        return this.testSuiteVersion;
    }

    public ToolType getToolType() {
        return this.toolType;
    }

    public boolean isCommercial() {
        return this.isCommercial;
    }

    /**
     * Add a test case result to the set of results for this tool or expected results file.
     *
     * @param tcr The test case result to add.
     */
    public void put(TestCaseResult tcr) {

        String testCaseKey = tcr.getTestID();

        // If we are using test case numbers, just check to make sure the test case number is within
        // a reasonable valid range, and if not, provide a warning.
        if (ExpectedResultsProvider.isBenchmarkStyleScoring()) {
            try {
                int testCaseNum = Integer.parseInt(testCaseKey);
                // This warning message is added just in case. It can be caused by a buggy parser or
                // invalid results file.
                if (testCaseNum <= 0 || testCaseNum > MAX_TEST_CASE_WARNING_NUMBER) {
                    System.out.println(
                            "WARNING: Did you really intend to add a test case result for test case: "
                                    + tcr.getTestCaseName()
                                    + " with TestID: "
                                    + testCaseKey
                                    + " and testCaseNum: "
                                    + testCaseNum);
                    new Exception().printStackTrace();
                }
            } catch (NumberFormatException e) {
                System.out.println(
                        "FATAL INTERNAL ERROR: testCaseKey: '"
                                + testCaseKey
                                + "' for test case: "
                                + tcr.getTestCaseName()
                                + " is supposed to be an integer.");
                System.exit(-1);
            }
        }

        // There is a list of results for each test case
        List<TestCaseResult> results = this.testCaseResults.get(testCaseKey);
        if (results == null) {
            // If there are no results yet for this test case, create a List.
            // Add this entry for this test case to the set of results
            results = new ArrayList<TestCaseResult>();
            this.testCaseResults.put(testCaseKey, results);
        }

        // Add this specific result to this test case's results
        results.add(tcr);
    }

    /**
     * Get all the test case results for the specified test case
     *
     * @param The test case number, for Benchmark style test cases, or test case name, for
     *     non-Benchmark style
     * @return The set of results for this test case
     */
    public List<TestCaseResult> getTestCaseResults(String tn) {
        // Because Benchmark style test case IDs are now the ID number with leading zeroes, we have
        // to pad any String that is too short so it matches properly. This is mostly for the unit
        // tests, not when scoring actual tools
        return this.testCaseResults.get(StringUtils.leftPad(tn, BenchmarkScore.TESTIDLENGTH, "0"));
    }

    /**
     * Get a Set of Keys into the Map of all the TestCaseResults for this TestSuite.
     *
     * @return The Set of Keys.
     */
    public Set<String> keySet() {
        return this.testCaseResults.keySet();
    }

    /**
     * Get the name of the tool. e.g., "IBM AppScan"
     *
     * @return Name of the tool.
     */
    public String getToolName() {
        return this.toolName;
    }

    /**
     * Get the name of the tool and its version together. e.g., "IBM AppScan v4.2". But if the tool
     * is commercial, and its in anonymous mode then don't include the version number as that could
     * give away the tool.
     *
     * @return Name of the tool.
     */
    public String getToolNameAndVersion() {
        if (!this.anonymous
                && this.toolVersion != null
                && !"".equals(this.toolVersion)
                && !(BenchmarkScore.config.anonymousMode && this.isCommercial)) {
            return this.toolName + " v" + this.toolVersion;
        }
        return this.toolName;
    }

    /**
     * Get the version of the tool these results are from.
     *
     * @return Version of the tool if determined. Null otherwise.
     */
    public String getToolVersion() {
        return this.toolVersion;
    }

    /**
     * Determines whether the provided filename (with or without path info) is a test case file in
     * this test suite or not.
     *
     * @param testCaseFilename The name of the test case file to match against
     * @return True if a test case file, false otherwise.
     */
    public boolean isTestCaseFile(String testCaseFilename) {
        return (getMatchingTestCaseName(getFileNameNoPath(testCaseFilename)) != null);
    }

    /**
     * Determines whether the provided filename (with or without path info) is a test case file in
     * this test suite or not.
     *
     * @param testCaseFilename The name of the test case file to match against
     * @return The full name (not just test ID) of the corresponding test case name, or null if not
     *     a match
     */
    public String getMatchingTestCaseName(String testCaseFilename) {
        testCaseFilename = getFileNameNoPath(testCaseFilename);
        if (ExpectedResultsProvider.isBenchmarkStyleScoring()) {
            if (testCaseFilename.startsWith(BenchmarkScore.TESTCASENAME)) return testCaseFilename;
        } else {
            // If filename exactly matches test case file name, return the filename.
            if (this.testCaseResults.get(testCaseFilename) != null) return testCaseFilename;
            // If not a match, trim off 1 character at a time from the end of the testCaseFilename
            // to see if there is a match. This is the equivalent of 'startswith', except it looks
            // for exact matches by key, rather than searching through ALL the testcases to see if
            // the current testCaseFilename starts with one of the expected testcase names.
            int tcFileNameLength = testCaseFilename.length();
            for (int i = 1; i < tcFileNameLength - 1; i++) {
                String filenameToCheck = testCaseFilename.substring(0, tcFileNameLength - i);
                if (this.testCaseResults.get(filenameToCheck) != null) return filenameToCheck;
            }
            // if no match, fall through to return null
        }
        return null;
    }

    /**
     * Returns the filename without any preceding path info, for both Unix and Windows path
     * separators.
     *
     * @param filename
     * @return The filename without any path info (if any)
     */
    public static String getFileNameNoPath(String filename) {
        // We look for / and \ and strip off everything before and including the path separator. We
        // check both path chars because the results could be generated on one platform and scored
        // on another with different path separators.
        int length = filename.length();
        if (filename.contains("/")) {
            filename = filename.substring(filename.lastIndexOf('/') + 1, length);
        }
        if (filename.contains("\\")) {
            filename = filename.substring(filename.lastIndexOf('\\') + 1, length);
        }
        return filename.trim();
    }

    /**
     * Sets the name of the tool. e.g., "HP Fortify"
     *
     * @param tool - Name of the tool.
     */
    public void setTool(String toolName) {
        this.toolName = toolName;
    }

    /**
     * This method anonymizes the tool name based on the type of tool it is and the count of
     * previous tools of the same type that also have been anonymized.
     */
    public void setAnonymous() {
        // System.out.println("Anonymizing tool: " + this.getTool() + " which is of type: " +
        // getToolType());
        this.anonymous = true;

        switch (getToolType()) {
            case SAST:
                {
                    if (nextCommercialSAST_ToolNumber < 10) {
                        this.setTool("SAST-0" + nextCommercialSAST_ToolNumber++);
                    } else this.setTool("SAST-" + nextCommercialSAST_ToolNumber++);
                    break;
                }
            case DAST:
                {
                    if (nextCommercialDAST_ToolNumber < 10) {
                        this.setTool("DAST-0" + nextCommercialDAST_ToolNumber++);
                    } else this.setTool("DAST-" + nextCommercialDAST_ToolNumber++);
                    break;
                }
            case IAST:
                {
                    if (nextCommercialIAST_ToolNumber < 10) {
                        this.setTool("IAST-0" + nextCommercialIAST_ToolNumber++);
                    } else this.setTool("IAST-" + nextCommercialIAST_ToolNumber++);
                    break;
                }
            case Hybrid:
                {
                    if (nextCommercialHybrid_ToolNumber < 10) {
                        this.setTool("HYBR-0" + nextCommercialHybrid_ToolNumber++);
                    } else this.setTool("HYBR-" + nextCommercialHybrid_ToolNumber++);
                }
        }
    }

    public void setToolVersion(String version) {
        this.toolVersion = version;
    }

    /**
     * Get the scan time for this tool if set.
     *
     * @return The scan time, or 'Unknown' if not set.
     */
    public String getTime() {
        return scanTime;
    }

    /**
     * Set the scan time for this tool as a string describing the time. E.g., 0:17:29, which means
     * 17 minutes 29 seconds. Formatted usually by using formatTime().
     *
     * @param elapsed The scan time.
     */
    public void setTime(String elapsed) {
        this.scanTime = elapsed;
    }

    /**
     * Parse the scan time out of the results file name. Grabs the integer value at the end of the
     * file after the last '-' in the filename, if specified.
     *
     * @param f The results file name.
     */
    public void setTime(File f) {
        String filename = f.getName();
        String time = filename.substring(filename.lastIndexOf('-') + 1, filename.lastIndexOf('.'));
        try {
            int seconds = Integer.parseInt(time);
            this.setTime(formatTime(seconds * 1000));
        } catch (Exception e) {
            this.setTime("Time not specified");
        }
    }

    /**
     * Get the total number of results for these TestResults.
     *
     * @return The total number of results.
     */
    public int getTotalResults() {
        return testCaseResults.size();
    }

    /**
     * Convert the time it took to compute these results into a label to add to the scorecard.
     *
     * @param millis - compute time in milliseconds
     * @return a String label of the compute time. (e.g., 1 Days 2:55:32)
     */
    public static String formatTime(long millis) {
        if (millis < 0) {
            throw new IllegalArgumentException("Duration must be greater than zero!");
        }

        long days = TimeUnit.MILLISECONDS.toDays(millis);
        millis -= TimeUnit.DAYS.toMillis(days);
        long hours = TimeUnit.MILLISECONDS.toHours(millis);
        millis -= TimeUnit.HOURS.toMillis(hours);
        long minutes = TimeUnit.MILLISECONDS.toMinutes(millis);
        millis -= TimeUnit.MINUTES.toMillis(minutes);
        long seconds = TimeUnit.MILLISECONDS.toSeconds(millis);

        StringBuilder sb = new StringBuilder(64);
        if (days > 0) {
            sb.append(days);
            if (days > 1) sb.append(" Days ");
            else sb.append(" Day ");
        }
        sb.append(hours);
        if (minutes > 9) sb.append(":");
        else sb.append(":0");
        sb.append(minutes);
        if (seconds > 9) sb.append(":");
        else sb.append(":0");
        sb.append(seconds);

        return (sb.toString());
    }

    /**
     * Convert the time it took to compute these results into a label to add to the scorecard.
     *
     * @param millis - compute time in milliseconds
     * @return a String label of the compute time. (e.g., 1 Days 2:55:32)
     */
    public static String formatTime(String millis) {

        String result;
        try {
            long time = Long.valueOf(millis);
            result = formatTime(time);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Provided value must be in integer in milliseconds. Value was: " + millis);
        }
        return result;
    }

    public String getShortName() {
        return this.toolName;
    }
}
