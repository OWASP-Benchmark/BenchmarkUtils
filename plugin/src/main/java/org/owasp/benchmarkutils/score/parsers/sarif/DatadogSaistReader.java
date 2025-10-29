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
 * @author Julien Delange
 * @created 2024
 */
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

/**
 * This reader is made for the datadog-saist-experiment tool available on <a
 * href="https://github.com/DataDog/datadog-saist-experiment">...</a>. It uses the SARIF file
 * produced by the AI-native SAST tool.
 */
public class DatadogSaistReader extends Reader {
    private static final String DATADOG_SAIST_TOOL_NAME = "datadog-saist";

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.filename().endsWith(".sarif")
                    && resultFile.isJson()
                    && resultFile
                            .json()
                            .getJSONArray("runs")
                            .getJSONObject(0)
                            .getJSONObject("tool")
                            .getJSONObject("driver")
                            .getString("name")
                            .equalsIgnoreCase(DATADOG_SAIST_TOOL_NAME)
                    && resultFile
                            .json()
                            .getJSONArray("runs")
                            .getJSONObject(0)
                            .getJSONObject("tool")
                            .getJSONObject("driver")
                            .has("version");
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Provide a direct mapping between a SAIST rule identifier and a CWE
     *
     * @param ruleId the rule identifier
     * @return the corresponding CWE identifier
     */
    private Type getTypeFromRuleId(String ruleId) {
        // Java rules
        if ("datadog/java-cmdi".equals(ruleId)) {
            return Type.COMMAND_INJECTION; // CWE-77
        }
        if ("datadog/java-sqli".equals(ruleId)) {
            return Type.SQL_INJECTION; // CWE-89
        }
        if ("datadog/java-xpathi".equals(ruleId)) {
            return Type.XPATH_INJECTION; // CWE-91
        }
        if ("datadog/java-xss".equals(ruleId)) {
            return Type.XSS; // CWE-79
        }

        // Go rules
        if ("datadog/go-cmdi".equals(ruleId)) {
            return Type.COMMAND_INJECTION; // CWE-77
        }
        if ("datadog/go-sqli".equals(ruleId)) {
            return Type.SQL_INJECTION; // CWE-89
        }
        if ("datadog/go-xpathi".equals(ruleId)) {
            return Type.XPATH_INJECTION; // CWE-91
        }
        if ("datadog/go-xss".equals(ruleId)) {
            return Type.XSS; // CWE-79
        }

        // Python rules
        if ("datadog/python-cmdi".equals(ruleId)) {
            return Type.COMMAND_INJECTION; // CWE-77
        }
        if ("datadog/python-sqli".equals(ruleId)) {
            return Type.SQL_INJECTION; // CWE-89
        }
        if ("datadog/python-xpathi".equals(ruleId)) {
            return Type.XPATH_INJECTION; // CWE-91
        }
        if ("datadog/python-xss".equals(ruleId)) {
            return Type.XSS; // CWE-79
        }

        return null;
    }

    // Not needed for SAIST since we have exact rule IDs
    // Keeping for potential future use with rule variations

    /**
     * Try to get the CWE from the violation object in the SARIF report.
     *
     * @param violation the violation object from the SARIF report
     * @return the CWE if found, 0 otherwise
     */
    private int getCweFromProperties(JSONObject violation) {
        try {
            // Check properties.tags for CWE information
            JSONObject properties = violation.getJSONObject("properties");
            if (properties.has("tags")) {
                JSONArray tags = properties.getJSONArray("tags");
                for (int k = 0; k < tags.length(); k++) {
                    String tag = tags.getString(k);
                    if (tag.toUpperCase().contains("CWE")) {
                        // Extract CWE number from various formats: CWE-89, CWE:89, cwe89, etc.
                        String cweStr = tag.replaceAll("(?i)cwe[-:]?", "").replaceAll("[^0-9]", "");
                        if (!cweStr.isEmpty()) {
                            return Integer.parseInt(cweStr);
                        }
                    }
                }
            }

            // Check if there's direct CWE property
            if (properties.has("cwe")) {
                return properties.getInt("cwe");
            }
        } catch (Exception e) {
            // Continue to try other methods if properties parsing fails
        }

        // Try to get CWE from rule metadata
        try {
            if (violation.has("rule")) {
                JSONObject rule = violation.getJSONObject("rule");
                if (rule.has("properties")) {
                    JSONObject ruleProps = rule.getJSONObject("properties");
                    if (ruleProps.has("cwe")) {
                        return ruleProps.getInt("cwe");
                    }
                }
            }
        } catch (Exception e) {
            return 0;
        }

        return 0;
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONArray runs = resultFile.json().getJSONArray("runs");

        TestSuiteResults tr =
                new TestSuiteResults("DatadogSaist", true, TestSuiteResults.ToolType.SAST);

        tr.setTime(resultFile.file());

        for (int i = 0; i < runs.length(); i++) {
            JSONObject run = runs.getJSONObject(i);

            JSONObject driver = run.getJSONObject("tool").getJSONObject("driver");
            if (!driver.has("name")
                    || !driver.getString("name").equalsIgnoreCase(DATADOG_SAIST_TOOL_NAME)) {
                continue;
            }

            tr.setToolVersion(driver.getString("version"));

            if (!run.has("results")) {
                continue;
            }

            JSONArray results = run.getJSONArray("results");

            for (int j = 0; j < results.length(); j++) {
                JSONObject result = results.getJSONObject(j);
                String ruleId = result.getString("ruleId");
                TestCaseResult tcr = new TestCaseResult();

                // First, try to get the CWE based on the rule id. If it fails, try to get it from
                // the properties of the violation.
                Type t = getTypeFromRuleId(ruleId);

                if (t != null) {
                    tcr.setCWE(t.number);
                    tcr.setCategory(t.id);
                } else {
                    // If no direct mapping found, try to get CWE from properties
                    int cweFromProperties = getCweFromProperties(result);
                    if (cweFromProperties != 0) {
                        tcr.setCWE(cweFromProperties);
                        tcr.setCategory("saist-cwe-" + cweFromProperties);
                    } else {
                        System.out.println(
                                "WARNING: DatadogSaist parser encountered unmapped rule: " + ruleId);
                        continue;
                    }
                }

                if (tcr.getCWE() == 0) {
                    continue;
                }

                if (!result.has("locations") || result.getJSONArray("locations").length() == 0) {
                    System.out.println(
                            "WARNING: DatadogSaist result missing locations for rule: " + ruleId);
                    continue;
                }

                JSONArray locations = result.getJSONArray("locations");
                String filename =
                        locations
                                .getJSONObject(0)
                                .getJSONObject("physicalLocation")
                                .getJSONObject("artifactLocation")
                                .getString("uri");

                filename = filename.substring(filename.lastIndexOf('/') + 1);
                if (!filename.startsWith(BenchmarkScore.TESTCASENAME)) {
                    continue;
                }

                int testnumber = testNumber(filename);
                tcr.setNumber(testnumber);

                // Get evidence/message from result
                String evidence = "";
                if (result.has("message") && result.getJSONObject("message").has("text")) {
                    evidence = result.getJSONObject("message").getString("text");
                } else {
                    evidence = "SAIST finding for rule: " + ruleId;
                }
                tcr.setEvidence(evidence);

                tr.put(tcr);
            }
        }
        return tr;
    }

    // Enumeration that contains the CWE and associated category for SAIST rules
    private enum Type {
        COMMAND_INJECTION(77),  // CWE-77 for SAIST rules
        SQL_INJECTION(89),      // CWE-89
        XPATH_INJECTION(91),    // CWE-91
        XSS(79);               // CWE-79

        private final int number;
        private final String id;

        Type(final int number) {
            this.number = number;
            this.id = "saist-" + name().toLowerCase().replaceAll("_", "-");
        }
    }
}
