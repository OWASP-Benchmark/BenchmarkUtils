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
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

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
        return toolDriver(firstRun(resultFile)).getString("name");
    }

    private static JSONObject firstRun(ResultFile resultFile) {
        return resultFile.json().getJSONArray("runs").getJSONObject(0);
    }

    private static JSONObject toolDriver(JSONObject run) {
        return run.getJSONObject("tool").getJSONObject("driver");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults testSuiteResults = testSuiteResults(resultFile);

        // TODO: Extract time from invocation
        testSuiteResults.setTime(resultFile.file()); // This grabs the scan time out of the filename (if present)

        JSONObject driver = toolDriver(firstRun(resultFile));
        if(driver.has("semanticVersion")) {
            testSuiteResults.setToolVersion(driver.getString("semanticVersion"));
        }

        parseResults(resultFile, testSuiteResults);

        return testSuiteResults;
    }

    private void parseResults(ResultFile resultFile, TestSuiteResults testSuiteResults) {
        JSONArray runs = resultFile.json().getJSONArray("runs");

        for (int i = 0; i < runs.length(); i++) {
            JSONObject run = runs.getJSONObject(i);

            Map<String, Integer> mappings = ruleCweMappings(run.getJSONObject("tool"));
            JSONArray results = run.getJSONArray("results");

            for (int j = 0; j < results.length(); j++) {
                TestCaseResult tcr = testCaseResultFor(results.getJSONObject(j), mappings);

                if (tcr != null) {
                    testSuiteResults.put(tcr);
                }
            }
        }
    }

    protected Map<String, Integer> ruleCweMappings(JSONObject tool) {
        switch (cweSourceType) {
            case TAG:
                return ruleCweMappingsByTag(tool);
            case FIELD:
                return ruleCweMappingsByField(tool);
            case CUSTOM:
                return customRuleCweMappings(tool);
            default:
                throw new IllegalArgumentException("Unknown cwe mapping source type");
        }
    }

    private Map<String, Integer> ruleCweMappingsByTag(JSONObject tool) {
        Map<String, Integer> mappings = new HashMap<>();

        for (JSONObject rule : extractRulesFrom(tool)) {
            JSONArray tags = rule.getJSONObject("properties").getJSONArray("tags");

            for (int j = 0; j < tags.length(); j++) {
                String tag = tags.getString(j).toLowerCase();

                if (tag.contains("cwe")) {
                    mappings.put(rule.getString("id"), mapCwe(extractCwe(tag)));
                }
            }
        }

        return mappings;
    }

    private static Set<JSONObject> extractRulesFrom(JSONObject tool) {
        Set<JSONObject> toolRules = new HashSet<>();

        JSONArray rules = tool.getJSONObject("driver").getJSONArray("rules");

        for (int i = 0; i < rules.length(); i++) {
            toolRules.add(rules.getJSONObject(i));
        }

        if (tool.has("extensions")) {
            JSONArray extensions = tool.getJSONArray("extensions");

            for (int i = 0; i < extensions.length(); i++) {
                JSONObject extension = extensions.getJSONObject(i);

                if (extension.has("rules")) {
                    JSONArray extensionRules = extension.getJSONArray("rules");

                    for (int j = 0; j < extensionRules.length(); j++) {
                        toolRules.add(extensionRules.getJSONObject(j));
                    }
                }
            }
        }

        return toolRules;
    }

    private Map<String, Integer> ruleCweMappingsByField(JSONObject tool) {
        Map<String, Integer> mappings = new HashMap<>();

        for (JSONObject rule : extractRulesFrom(tool)) {
            int cwe = extractCwe(rule.getJSONObject("properties").getJSONArray("cwe").getString(0));

            mappings.put(rule.getString("id"), mapCwe(cwe));
        }

        return mappings;
    }

    public Map<String, Integer> customRuleCweMappings(JSONObject driver) {
        throw new IllegalArgumentException(
            "SARIF Reader using custom cwe mappings MUST overwrite mapping method.");
    }

    private TestSuiteResults testSuiteResults(ResultFile resultFile) {
        return new TestSuiteResults(
            toolName(resultFile), isCommercial, TestSuiteResults.ToolType.SAST);
    }

    /*
     * Returns display tool name (for final report). By default, the SARIF tool name will be used. Overwrite if custom name is necessary.
     */
    public String toolName(ResultFile resultFile) {
        return sarifToolName(resultFile);
    }

    private TestCaseResult testCaseResultFor(JSONObject result, Map<String, Integer> mappings) {
        TestCaseResult tcr = new TestCaseResult();

        String className = extractFilename(resultUri(result));

        if (!className.startsWith(BenchmarkScore.TESTCASENAME)) {
            return null;
        }

        String ruleId = result.getString("ruleId");

        int cwe = mappings.getOrDefault(ruleId, -1);

        if (cwe == -1) {
            return null;
        }

        String evidence = result.getJSONObject("message").getString("text");

        tcr.setCWE(cwe);
        tcr.setCategory(ruleId);
        tcr.setEvidence(evidence);
        tcr.setConfidence(0);
        tcr.setNumber(testNumber(className));

        return tcr;
    }

    private static String resultUri(JSONObject result) {
        return result.getJSONArray("locations")
            .getJSONObject(0)
            .getJSONObject("physicalLocation")
            .getJSONObject("artifactLocation")
            .getString("uri");
    }

    /*
     * Allows extending classes to map/change detected cwe numbers to match Benchmark expected numbers (if required)
     */
    public int mapCwe(int cwe) {
        return cwe;
    }

    /*
     * Extracts any number from given string (assuming it's a CWE number)
     */
    public static int extractCwe(String input) {
        Matcher matcher = Pattern.compile("\\d+").matcher(input);

        if (matcher.find()) {
            return parseInt(matcher.group(0));
        } else {
            throw new IllegalArgumentException("ERROR: Could not extract number from input '" + input + "'");
        }
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
