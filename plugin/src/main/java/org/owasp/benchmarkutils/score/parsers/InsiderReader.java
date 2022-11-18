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
 * <p>This reader reads JSON reports from the Insider open source tool at:
 * https://github.com/insidersec/insider
 *
 * @author Sascha Knoop
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class InsiderReader extends Reader {

    private static final String[] expectedVulnerabilityKeys = {
        "cvss", "cwe", "line", "class", "vul_id", "method", "column", "description"
    };

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return hasExpectedKeys(
                    resultFile.json().getJSONArray("vulnerabilities").getJSONObject(0));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean hasExpectedKeys(JSONObject vulnerability) {
        for (String key : expectedVulnerabilityKeys) {
            if (!vulnerability.has(key)) {
                return false;
            }
        }

        return true;
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Insider", false, TestSuiteResults.ToolType.SAST);

        JSONArray arr = resultFile.json().getJSONArray("vulnerabilities");

        for (int i = 0; i < arr.length(); i++) {
            TestCaseResult tcr = parseTestCaseResult(arr.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    private TestCaseResult parseTestCaseResult(JSONObject finding) {
        try {
            String filename = filename(finding);

            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();

                tcr.setNumber(testNumber(filename));
                int cwe = cweNumber(finding);
                tcr.setCWE(cwe);

                return tcr;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private int cweNumber(JSONObject finding) {
        String cwe = finding.getString("cwe").substring(4);

        switch (cwe) {
            case "78":
                return CweNumber.COMMAND_INJECTION;
            case "326":
            case "327":
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "330":
                return CweNumber.WEAK_RANDOM;
            case "532":
                return CweNumber.SENSITIVE_LOGFILE;

            default:
                System.out.println(
                        "INFO: Found following CWE which we haven't seen before: " + cwe);
                return Integer.parseInt(cwe);
        }
    }

    private String filename(JSONObject vuln) {
        String className = vuln.getString("class");
        return className.substring(0, className.indexOf(' '));
    }
}
