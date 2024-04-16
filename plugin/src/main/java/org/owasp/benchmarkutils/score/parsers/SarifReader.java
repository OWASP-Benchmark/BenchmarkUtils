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

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

import java.util.HashMap;
import java.util.Map;

import static java.lang.Integer.parseInt;

public abstract class SarifReader extends Reader {

    private final String expectedToolName;
    private final boolean isCommercial;
    private final CweSourceType cweSourceType;

    public SarifReader(String expectedToolName, boolean isCommercial, CweSourceType cweSourceType) {
        this.expectedToolName = expectedToolName;
        this.isCommercial = isCommercial;
        this.cweSourceType = cweSourceType;
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.isJson() && sarifToolName(resultFile).equals(expectedToolName);
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

        TestSuiteResults testSuiteResults = testSuiteResults(resultFile);

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

            int cwe = mappings.getOrDefault(ruleId, -1);

            if (cwe == -1) {
                System.out.println("No CWE # present for rule '" + ruleId + "'");
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

    protected Map<String, Integer> ruleCweMappings(JSONArray rules) {
        switch (cweSourceType) {
            case TAG:
                return ruleCweMappingsByTag(rules);
            case FIELD:
                return ruleCweMappingsByField(rules);
            case CUSTOM:
                return customRuleCweMappings(rules);
            default:
                throw new IllegalArgumentException("Unknown cwe mapping source type");
        }
    }

    private Map<String, Integer> ruleCweMappingsByTag(JSONArray rules) {
        Map<String, Integer> mappings = new HashMap<>();

        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);

            JSONArray tags = rule.getJSONObject("properties").getJSONArray("tags");

            for (int j = 0; j < tags.length(); j++) {
                String tag = tags.getString(j);

                if (tag.startsWith("CWE")) {
                    mappings.put(rule.getString("id"), extractCwe(tag));
                }
            }
        }

        return mappings;
    }

    private Map<String, Integer> ruleCweMappingsByField(JSONArray rules) {
        Map<String, Integer> mappings = new HashMap<>();

        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);

            int cwe = extractCwe(rule.getJSONObject("properties").getJSONArray("cwe").getString(0));

            mappings.put(rule.getString("id"), cwe);
        }

        return mappings;
    }

    private Map<String, Integer> customRuleCweMappings(JSONArray rules) {
        throw new IllegalArgumentException(
            "SARIF Reader using custom cwe mappings MUST overwrite mapping method.");
    }

    private TestSuiteResults testSuiteResults(ResultFile resultFile) {
        return new TestSuiteResults(
            sarifToolName(resultFile), isCommercial, TestSuiteResults.ToolType.SAST);
    }

    private static String resultUri(JSONObject result) {
        return result.getJSONArray("locations")
            .getJSONObject(0)
            .getJSONObject("physicalLocation")
            .getJSONObject("artifactLocation")
            .getString("uri");
    }

    public static int extractCwe(String input) {
        // TODO: Replace with Regex
        return parseInt(
            input.toLowerCase().replace("external/cwe/", "").split("cwe-")[1].split(":")[0]);
    }

    /*
     * Although the SARIF standard suggests that CWE numbers should not be a rule tag, most tools use them or a
     * separate field for CWE number. As of today, no supported tool seems to follow the SARIF recommendation using
     * taxonomies.
     *
     * See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html#_Toc10540974
     */
    public enum CweSourceType {
        TAG, // CWE-123, sometimes with prefix
        FIELD, // separate field containing CWE number
        CUSTOM // custom mapping, e. g. static table
    }
}
