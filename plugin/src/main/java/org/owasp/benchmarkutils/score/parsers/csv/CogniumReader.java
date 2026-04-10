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
 * @author Cognium Labs
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.csv;

import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.parsers.Reader;

/**
 * Reader for <a href="https://cognium.dev">Cognium</a> results generated via:
 *
 * <pre>cognium scan &lt;path&gt; --format owasp-benchmark --output results.csv</pre>
 *
 * <p>The output format is a CSV with one row per detected finding:
 *
 * <pre>
 * # test name,category,CWE,real vulnerability
 * BenchmarkTest00001,cmdi,78,true
 * BenchmarkTest00003,sqli,89,true
 * </pre>
 *
 * <p>Only positive detections are emitted; test cases not present are treated as negatives by the
 * scorecard generator.
 */
public class CogniumReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).startsWith("# test name,category,CWE");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Cognium", false, TestSuiteResults.ToolType.SAST);

        List<String> rows = resultFile.contentAsRows();

        // Row 0 is the header comment; data starts at row 1
        for (int i = 1; i < rows.size(); i++) {
            String row = rows.get(i).trim();
            if (row.isEmpty()) {
                continue;
            }

            String[] parts = row.split(",", -1);
            if (parts.length < 4) {
                continue;
            }

            String testName = parts[0].trim();
            if (!testName.startsWith(BenchmarkScore.TESTCASENAME)) {
                continue;
            }

            int cwe;
            try {
                cwe = Integer.parseInt(parts[2].trim());
            } catch (NumberFormatException e) {
                System.out.println(
                        "WARNING: Cognium results file contained invalid CWE on row " + i + ": " + row);
                continue;
            }

            TestCaseResult tcr = new TestCaseResult();
            tcr.setNumber(testNumber(testName));
            tcr.setCWE(cwe);
            tcr.setCategory(parts[1].trim());
            tr.put(tcr);
        }

        return tr;
    }
}
