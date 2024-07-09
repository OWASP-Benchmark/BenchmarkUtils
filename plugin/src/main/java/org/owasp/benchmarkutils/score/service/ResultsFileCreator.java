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
 * @author Sascha Knoop
 * @created 2024
 */
package org.owasp.benchmarkutils.score.service;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;

/**
 * This produces the .csv of all the results for this tool. It's basically the expected results file
 * with a couple of extra columns in it to say what the actual result for this tool was per test
 * case and whether that result was a pass or fail.
 */
public class ResultsFileCreator {

    private final File scoreCardDir;
    private final TestSuiteName testSuiteName;

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

    public ResultsFileCreator(File scoreCardDir, TestSuiteName testSuiteName) {
        this.scoreCardDir = scoreCardDir;
        this.testSuiteName = testSuiteName;
    }

    public String createFor(TestSuiteResults actual) {
        File resultsFile = new File(resultsFilename(actual));
        boolean fullDetails = isFullDetails(actual);

        try (FileOutputStream fos = new FileOutputStream(resultsFile, false);
                PrintStream ps = new PrintStream(fos)) {

            writeHeader(ps, fullDetails, actual.getTestSuiteVersion());

            actual.keySet().forEach(testNumber -> appendRow(ps, actual, testNumber, fullDetails));

            System.out.println("Actual results file generated: " + resultsFile.getAbsolutePath());

            return resultsFile.getName();
        } catch (FileNotFoundException e) {
            System.out.println(
                    "ERROR: Can't create actual results file: " + resultsFile.getAbsolutePath());
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        return null; // Should have returned results file name earlier if successful
    }

    private boolean isFullDetails(TestSuiteResults actual) {
        Iterator<Integer> iterator = actual.keySet().iterator();

        return iterator.hasNext() && (actual.get(iterator.next()).get(0).getSource() != null);
    }

    private void writeHeader(PrintStream ps, boolean fullDetails, String testSuiteVersion) {
        ps.print("# test name, category, CWE, ");

        if (fullDetails) {
            ps.print("source, data flow, sink, ");
        }

        ps.print(
                "real vulnerability, identified by tool, pass/fail, "
                        + testSuiteName.simpleName()
                        + " version: "
                        + testSuiteVersion);

        ps.println(", Actual results generated: " + sdf.format(new Date()));
    }

    private void appendRow(
            PrintStream ps, TestSuiteResults actual, Integer testNumber, boolean fullDetails) {
        TestCaseResult actualResult = actual.get(testNumber).get(0);
        boolean isReal = actualResult.isTruePositive();
        boolean passed = actualResult.isPassed();

        ps.print(actualResult.getName());
        ps.print(", " + actualResult.getCategory());
        ps.print(", " + actualResult.getCWE());

        if (fullDetails) {
            ps.print(", " + actualResult.getSource());
            ps.print(", " + actualResult.getDataFlow());
            ps.print(", " + actualResult.getSink());
        }

        ps.print(", " + isReal);
        ps.print(", " + (isReal == passed));
        ps.println(", " + (passed ? "pass" : "fail"));
    }

    private String resultsFilename(TestSuiteResults actual) {
        return MessageFormat.format(
                "{0}{1}{2}_v{3}_Scorecard_for_{4}.csv",
                scoreCardDir.getAbsolutePath(),
                File.separator,
                testSuiteName.simpleName(),
                actual.getTestSuiteVersion(),
                actual.getToolNameAndVersion().replace(' ', '_'));
    }
}
