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
package org.owasp.benchmarkutils.score.parsers;

import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public abstract class SarifReader extends Reader {

    private static final int INVALID_RULE_ID = -1;

    protected abstract String expectedSarifToolName();

    protected abstract boolean isCommercial();

    protected abstract Map<String, Integer> ruleCweMappings(JSONArray rules);

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.isJson() && sarifToolName(resultFile).equals(expectedSarifToolName());
        } catch (Exception e) {
            return false;
        }
    }

    private String sarifToolName(ResultFile resultFile) {
        return toolDriver(resultFile).getString("name");
    }

    private static JSONObject toolDriver(ResultFile resultFile) {
        return firstRun(resultFile).getJSONObject("tool").getJSONObject("driver");
    }

    private static JSONObject firstRun(ResultFile resultFile) {
        return resultFile.json().getJSONArray("runs").getJSONObject(0);
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONObject driver = toolDriver(resultFile);

        Map<String, Integer> mappings = ruleCweMappings(driver.getJSONArray("rules"));

        TestSuiteResults testSuiteResults =
                new TestSuiteResults(
                        sarifToolName(resultFile), isCommercial(), TestSuiteResults.ToolType.SAST);

        testSuiteResults.setToolVersion(driver.getString("semanticVersion"));

        JSONArray results = firstRun(resultFile).getJSONArray("results");

        for (int i = 0; i < results.length(); i++) {
            JSONObject result = results.getJSONObject(i);

            String className = extractFilename(resultUri(result));

            if (!className.startsWith(BenchmarkScore.TESTCASENAME)) {
                continue;
            }

            TestCaseResult tcr = new TestCaseResult();

            String ruleId = result.getString("ruleId");

            int cwe = mappings.getOrDefault(ruleId, INVALID_RULE_ID);

            if (cwe == INVALID_RULE_ID) {
                System.out.println("CWE # not parseable from: " + ruleId);
                continue;
            }

            String evidence = result.getJSONObject("message").getString("text");

            tcr.setCWE(cwe);
            tcr.setCategory(ruleId);
            tcr.setEvidence(evidence);
            tcr.setConfidence(0);
            tcr.setNumber(testNumber(className));

            testSuiteResults.put(tcr);
        }

        return testSuiteResults;
    }

    private static String resultUri(JSONObject result) {
        return result.getJSONArray("locations")
                .getJSONObject(0)
                .getJSONObject("physicalLocation")
                .getJSONObject("artifactLocation")
                .getString("uri");
    }
}
