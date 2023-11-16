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
 * @author Cédric Fabianski
 * @created 2023
 */
package org.owasp.benchmarkutils.score.parsers;

import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class BearerReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.json().has("findings")
                && resultFile.json().has("source")
                && Objects.equals(resultFile.json().getString("source"), "Bearer");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Bearer", false, TestSuiteResults.ToolType.SAST);

        JSONArray results = resultFile.json().getJSONArray("findings");
        tr.setToolVersion(resultFile.json().getString("version"));

        // results
        for (int i = 0; i < results.length(); i++) {
            TestCaseResult tcr = parseBearerFindings(results.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private int translate(int cwe) {
        switch (cwe) {
            case 326:
                return CweNumber.WEAK_CRYPTO_ALGO;
            case 327:
                return CweNumber.WEAK_HASH_ALGO;
            default:
                return cwe;
        }
    }

    private TestCaseResult parseBearerFindings(JSONObject result) {
        try {
            String className = result.getString("filename");
            className = (className.substring(className.lastIndexOf('/') + 1)).split("\\.")[0];
            if (className.startsWith(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();

                // CWE
                String cweString = result.getJSONArray("cwe_ids").getString(0);
                int cwe = Integer.parseInt(cweString);

                try {
                    cwe = translate(cwe);
                } catch (NumberFormatException ex) {
                    System.out.println(
                            "CWE # not parseable from: " + result.getJSONObject("cwe_ids"));
                }

                // evidence
                String evidence = result.getString("id");

                tcr.setCWE(cwe);
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
}
