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
 * @author Nacho Guisado Obregón, Dave Wichers
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SemgrepReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.json().has("results")
                && resultFile.json().has("errors");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Semgrep", false, TestSuiteResults.ToolType.SAST);

        JSONArray results = resultFile.json().getJSONArray("results");

        // results
        for (int i = 0; i < results.length(); i++) {
            TestCaseResult tcr = parseSemgrepFindings(results.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    /**
     * Maps detected CWE number to one that BenchmarkScore expects.
     *
     * @param cwe reported CWE number
     * @return fixed (or same) CWE number
     */
    private CweNumber translate(int cwe) {
        switch (cwe) {
            case 326:
            case 696: // Incorrect Behavior Order
                return CweNumber.WEAK_CRYPTO_ALGO;
            case 1004:
                return CweNumber.INSECURE_COOKIE;
        }

        return CweNumber.lookup(cwe);
    }

    private TestCaseResult parseSemgrepFindings(JSONObject result) {
        try {
            String className = result.getString("path");
            className = (className.substring(className.lastIndexOf('/') + 1)).split("\\.")[0];
            if (className.startsWith(BenchmarkScore.TESTCASENAME)) {

                TestCaseResult tcr = new TestCaseResult();

                JSONObject extra = result.getJSONObject("extra");
                JSONObject metadata = extra.getJSONObject("metadata");

                // CWE
                String cweString = getStringOrFirstArrayIndex(metadata, "cwe");
                CweNumber cwe = CweNumber.DONTCARE;
                try {
                    int cweNumber = Integer.parseInt(cweString.split(":")[0].split("-")[1]);
                    cwe = translate(cweNumber);
                } catch (NumberFormatException ex) {
                    System.out.println("CWE # not parseable from: " + metadata.getString("cwe"));
                }

                // category
                String category = getStringOrFirstArrayIndex(metadata, "owasp");

                // evidence
                String evidence = result.getString("check_id");

                tcr.setCWE(cwe);
                tcr.setCategory(category);
                tcr.setEvidence(evidence);
                tcr.setConfidence(0);
                tcr.setNumber(testNumber(className));

                return tcr;
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    private static String getStringOrFirstArrayIndex(JSONObject metadata, String key) {
        if (metadata.get(key) instanceof JSONArray) {
            return metadata.getJSONArray(key).getString(0);
        } else {
            return metadata.getString(key);
        }
    }
}
