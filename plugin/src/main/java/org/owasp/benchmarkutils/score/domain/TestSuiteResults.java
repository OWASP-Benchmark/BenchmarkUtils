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
package org.owasp.benchmarkutils.score.domain;

import static java.lang.Long.parseLong;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.TimeUnit;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.domain.exception.NoToolNameProvided;
import org.owasp.benchmarkutils.score.domain.exception.NoToolTypeProvided;

/**
 * TestSuiteResults contains the expected results for each test case in a test suite, if its
 * initialized with the expected results file. Or the actual results for a single tool against each
 * test case in test suite.
 */
public class TestSuiteResults {

    private final boolean commercial;
    private String toolName;
    private final ToolType toolType;

    private String testSuiteVersion = "notSet";
    private String toolVersion = null;

    private final Map<Integer, List<TestCaseResult>> testCaseResults = new TreeMap<>();

    /** Used to track if this tool has been anonymized */
    private boolean anonymous;

    // TODO: Refactor to generation class
    private String time = "Unknown"; // Scan time. e.g., '0:17:29'
    private static int nextCommercialSAST_ToolNumber = 1;
    private static int nextCommercialDAST_ToolNumber = 1;
    private static int nextCommercialIAST_ToolNumber = 1;
    private static int nextCommercialHybrid_ToolNumber = 1;

    public TestSuiteResults(String toolName, boolean commercial, ToolType toolType) {
        assertToolName(toolName);
        assertToolType(toolType);

        this.commercial = commercial;
        this.toolName = toolName;
        this.toolType = toolType;
    }

    private static void assertToolName(String toolName) {
        if (toolName == null || toolName.isEmpty()) {
            throw new NoToolNameProvided();
        }
    }

    private static void assertToolType(ToolType toolType) {
        if (toolType == null) {
            throw new NoToolTypeProvided();
        }
    }

    /** Set the version number for this specific set of TestResults */
    public void setTestSuiteVersion(String version) {
        this.testSuiteVersion = version;
    }

    public String getTestSuiteVersion() {
        return this.testSuiteVersion;
    }

    public ToolType getToolType() {
        return toolType;
    }

    public boolean isCommercial() {
        return commercial;
    }

    /**
     * Add a test case result to the set of results for this tool.
     *
     * @param tcr The test case result to add.
     */
    public void add(TestCaseResult tcr) {
        int testNumber = tcr.getNumber();

        if (isImpossibleTestNumber(testNumber)) {
            System.out.println("WARN: Ignoring test case result for test number " + testNumber);
            return;
        }

        List<TestCaseResult> results = testCaseResults.getOrDefault(testNumber, new ArrayList<>());
        results.add(tcr);
        testCaseResults.put(testNumber, results);
    }

    private boolean isImpossibleTestNumber(int testNumber) {
        return testNumber <= 0 || testNumber > 10000;
    }

    public List<TestCaseResult> resultsFor(int number) {
        return testCaseResults.get(number);
    }

    /**
     * Returns a Set of all test numbers having at least one result.
     *
     * @return The Set of Keys.
     */
    public Set<Integer> testNumbers() {
        return testCaseResults.keySet();
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
    public String getDisplayName(boolean anonymousMode) {
        if (!anonymous && toolVersionPresent() && !(anonymousMode && isCommercial())) {
            return toolName + " v" + toolVersion;
        }
        return this.toolName;
    }

    private boolean toolVersionPresent() {
        return toolVersion != null && !toolVersion.isEmpty();
    }

    /**
     * Get the version of the tool these results are from.
     *
     * @return Version of the tool if determined. Null otherwise.
     */
    public String getToolVersion() {
        return toolVersion;
    }

    /**
     * Sets the name of the tool. e.g., "HP Fortify"
     *
     * @param toolName - Name of the tool.
     */
    public void setToolName(String toolName) {
        assertToolName(toolName);

        this.toolName = toolName;
    }

    public void setToolVersion(String version) {
        this.toolVersion = version;
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
     * Get the scan time for this tool if set.
     *
     * @return The scan time, or 'unknown' if not set.
     */
    public String getTime() {
        return time;
    }

    /**
     * Set the scan time for this tool as a string describing the time. E.g., 0:17:29, which means
     * 17 minutes 29 seconds. Formatted usually by using formatTime().
     *
     * @param elapsed The scan time.
     */
    public void setTime(String elapsed) {
        this.time = elapsed;
    }

    /**
     * This method anonymizes the tool name based on the type of tool it is and the count of
     * previous tools of the same type that also have been anonymized.
     */
    public void setAnonymous() {
        this.anonymous = true;

        switch (getToolType()) {
            case SAST:
                {
                    if (nextCommercialSAST_ToolNumber < 10) {
                        setToolName("SAST-0" + nextCommercialSAST_ToolNumber++);
                    } else {
                        setToolName("SAST-" + nextCommercialSAST_ToolNumber++);
                    }
                    break;
                }
            case DAST:
                {
                    if (nextCommercialDAST_ToolNumber < 10) {
                        setToolName("DAST-0" + nextCommercialDAST_ToolNumber++);
                    } else {
                        setToolName("DAST-" + nextCommercialDAST_ToolNumber++);
                    }
                    break;
                }
            case IAST:
                {
                    if (nextCommercialIAST_ToolNumber < 10) {
                        setToolName("IAST-0" + nextCommercialIAST_ToolNumber++);
                    } else {
                        setToolName("IAST-" + nextCommercialIAST_ToolNumber++);
                    }
                    break;
                }
            case Hybrid:
                {
                    if (nextCommercialHybrid_ToolNumber < 10) {
                        setToolName("HYBR-0" + nextCommercialHybrid_ToolNumber++);
                    } else {
                        setToolName("HYBR-" + nextCommercialHybrid_ToolNumber++);
                    }
                }
        }
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

            if (days > 1) {
                sb.append(" Days ");
            } else {
                sb.append(" Day ");
            }
        }

        sb.append(hours);

        if (minutes > 9) {
            sb.append(":");
        } else {
            sb.append(":0");
        }

        sb.append(minutes);

        if (seconds > 9) {
            sb.append(":");
        } else {
            sb.append(":0");
        }

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
        try {
            return formatTime(parseLong(millis));
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Provided value must be in integer in milliseconds. Value was: " + millis);
        }
    }
}
