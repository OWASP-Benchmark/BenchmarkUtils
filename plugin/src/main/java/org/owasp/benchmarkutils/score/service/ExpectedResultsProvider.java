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
import static org.owasp.benchmarkutils.score.parsers.Reader.testNumber;

import java.io.IOException;
import java.util.Optional;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ExpectedResultsProvider {

    private static final String PREFIX = " version: ";

    private static final String TEST_NAME = "# test name";
    private static final String CATEGORY = " category";
    private static final String REAL_VULNERABILITY = " real vulnerability";
    private static final String CWE = " cwe";

    private static final String SOURCE = " source";
    private static final String DATA_FLOW = " vuln src";
    private static final String SINK = " vuln df";

    public static TestSuiteResults parse(ResultFile resultFile) throws IOException {
        TestSuiteResults tr = new TestSuiteResults("Expected", true, null);

        try (final CSVParser parser = resultFile.csvRecords()) {
            setResultsMetadata(parser, tr);

            String testCaseName = tr.getTestSuiteName() + BenchmarkScore.TEST;

            for (CSVRecord record : parser) {
                if (record.get(TEST_NAME).startsWith(tr.getTestSuiteName() + BenchmarkScore.TEST)) {
                    TestCaseResult tcr = new TestCaseResult();

                    tcr.setTestCaseName(record.get(TEST_NAME).trim());
                    tcr.setCategory(record.get(CATEGORY).trim());
                    tcr.setTruePositive(parseBoolean(record.get(REAL_VULNERABILITY).trim()));
                    tcr.setCWE(parseInt(record.get(CWE).trim()));
                    tcr.setNumber(testNumber(record.get(TEST_NAME).trim(), testCaseName));

                    if (isExtendedResultsFile(parser)) {
                        tcr.setSource(record.get(SOURCE).trim());
                        tcr.setDataFlow(record.get(DATA_FLOW).trim());
                        tcr.setSink(record.get(SINK).trim());
                    }

                    tr.put(tcr);
                }
            }
        }

        return tr;
    }

    private static void setResultsMetadata(CSVParser parser, TestSuiteResults tr)
            throws IOException {
        Optional<String> maybeVersionHeader =
                parser.getHeaderMap().keySet().stream().filter(h -> h.contains(PREFIX)).findFirst();

        if (maybeVersionHeader.isEmpty()) {
            String versionNumError =
                    "Couldn't find " + PREFIX + " on first line of expected results file";
            System.out.println(versionNumError);
            throw new IOException(versionNumError);
        }

        String versionHeader = maybeVersionHeader.get();

        int start = versionHeader.indexOf(PREFIX);

        final String testSuiteName = versionHeader.substring(0, start).trim();

        start += PREFIX.length();

        tr.setTestSuiteName(testSuiteName);
        tr.setTestSuiteVersion(versionHeader.substring(start));
    }

    private static boolean isExtendedResultsFile(CSVParser parser) {
        return parser.getHeaderNames().contains(SOURCE);
    }
}
