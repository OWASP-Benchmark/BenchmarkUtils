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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Sascha Knoop
 * @created 2024
 */
package org.owasp.benchmarkutils.score.service;

import static java.lang.Boolean.parseBoolean;
import static java.lang.Integer.parseInt;

import java.io.IOException;
import java.util.List;
import java.util.Optional;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;

public class ExpectedResultsProvider {

    // The following are column titles or elements in the expected results file
    public static final String PREFIX = " version: ";

    public static final String TEST_NAME = "# test name";
    public static final String CATEGORY = "category";
    public static final String REAL_VULNERABILITY = "real vulnerability";
    public static final String CWE = "cwe";

    public static final String SOURCE = "source";
    public static final String DATA_FLOW = "data flow";
    public static final String SINK = "sink";

    private static boolean standardBenchmarkStyleScoring;
    private static TestSuiteResults expectedResults;

    public static TestSuiteResults parse(ResultFile resultFile) throws IOException {
        TestSuiteResults tr = new TestSuiteResults("Expected", true, null);

        try (final CSVParser parser = resultFile.csvRecords()) {

            List<CSVRecord> allExpectedResults = parser.getRecords();

            CSVRecord firstRecord = allExpectedResults.get(0);
            // setExpectedResultsMetadata() has side effect of setting
            // BenchmarkScore.TESTSUITENAME, BenchmarkScore.TESTCASENAME, and
            // ExpectedResultsProvider.standardBenchmarkStyleScoring
            setExpectedResultsMetadata(parser, firstRecord, tr);

            // Parse all the expected results
            for (CSVRecord record : allExpectedResults) {
                TestCaseResult tcr = new TestCaseResult();

                String testCaseFileName = record.get(TEST_NAME);
                tcr.setTestCaseName(testCaseFileName);
                //                tcr.setCategory(record.get(CATEGORY));
                tcr.setTruePositive(parseBoolean(record.get(REAL_VULNERABILITY)));
                int cwe = parseInt(record.get(CWE));
                tcr.setCWE(cwe);
                //                tcr.setNumber(testNumber(record.get(TEST_NAME), testCaseName));

                if (TestCaseResult.UNMAPPED_CATEGORY.equals(tcr.getCategory())) {
                    System.out.println(
                            "FATAL ERROR: CWE metadata missing for CWE: "
                                    + cwe
                                    + " specified in results file: "
                                    + resultFile.filename()
                                    + ". Add missing data to "
                                    + Categories.FILENAME
                                    + " to address.");
                    System.exit(-1);
                }

                // Map this expected test case result CWE to its associated CategoryGroup, if
                // CategoryGroups enabled
                tcr.setCategoryGroup(cwe);

                // This method sets the expected result testID based on the scoring style,
                // previously determined
                // DRW TODO: Combine with setTestCaseName in future?
                tcr.setExpectedResultTestID(testCaseFileName);

                if (isExtendedResultsFile(parser)) {
                    tcr.setSource(record.get(SOURCE).trim());
                    tcr.setDataFlow(record.get(DATA_FLOW).trim());
                    tcr.setSink(record.get(SINK).trim());
                }

                tr.put(tcr);
            }
        }

        // Set static variable so any class can access the expected results
        expectedResults = tr;

        return tr;
    }

    /**
     * The expected results for this scoring run.
     *
     * @return The expected results object.
     */
    public static TestSuiteResults getExpectedResults() {
        if (expectedResults == null) {
            System.out.println(
                    "FATAL INTERNAL ERROR: Expected Results for this scoring run not initialized yet.");
            System.exit(-1);
        }
        return expectedResults;
    }

    /**
     * Whether standard Benchmark style test case file names are being scored per the expected
     * results file.
     *
     * @return True if so, false otherwise
     */
    public static boolean isBenchmarkStyleScoring() {
        return standardBenchmarkStyleScoring;
    }

    private static void setExpectedResultsMetadata(
            CSVParser parser, CSVRecord firstRecord, TestSuiteResults tr) throws IOException {
        Optional<String> maybeVersionHeader =
                parser.getHeaderMap().keySet().stream().filter(h -> h.contains(PREFIX)).findFirst();

        if (maybeVersionHeader.isEmpty()) {
            String versionNumError =
                    "ERROR: Couldn't find " + PREFIX + " on first line of expected results file";
            System.out.println(versionNumError);
            throw new IOException(versionNumError);
        }

        String versionHeader = maybeVersionHeader.get();

        int start = versionHeader.indexOf(PREFIX);

        String testSuiteName = versionHeader.substring(0, start).trim();

        // These values must be set here before parsing any expected/actual results
        // Maybe these two statics should be moved to ExpectedResultsProvider??
        BenchmarkScore.TESTSUITENAME = new TestSuiteName(testSuiteName);
        BenchmarkScore.TESTCASENAME = testSuiteName + BenchmarkScore.TEST;

        start += PREFIX.length();

        tr.setTestSuiteName(testSuiteName);

        tr.setTestSuiteVersion(versionHeader.substring(start));

        // Now check the 1st row of results to determine the scoring style
        if (firstRecord
                .get(TEST_NAME)
                .trim()
                .startsWith(tr.getTestSuiteName() + BenchmarkScore.TEST)) {
            ExpectedResultsProvider.standardBenchmarkStyleScoring = true;
            System.out.println(
                    "INFO: Using Default Benchmark style scoring based on contents of supplied expected results file.");
        } else {
            ExpectedResultsProvider.standardBenchmarkStyleScoring = false;
            System.out.println(
                    "INFO: Using non-Benchmark style scoring based on contents of supplied expected results file.");
        }
    }

    private static boolean isExtendedResultsFile(CSVParser parser) {
        return parser.getHeaderNames().contains(SOURCE);
    }
}
