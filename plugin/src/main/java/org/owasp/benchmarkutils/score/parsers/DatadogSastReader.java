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
 * This reader is made for the datadog-static-analyzer available on
 * <a href="https://github.com/DataDog/datadog-static-analyzer">...</a>.
 * It uses the SARIF file produces by the tool.
 */
public class DatadogSastReader extends Reader {
    private static final String DATADOG_TOOL_NAME = "datadog-static-analyzer";

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
                            .equalsIgnoreCase(DATADOG_TOOL_NAME)
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
     * Provide a direct mapping between a rule identifier and a CWE
     *
     * @param ruleId the rule identifier
     * @return the corresponding CWE identifier
     */
    private Type getTypeFromRuleId(String ruleId) {
        if (ruleId.equalsIgnoreCase("java-security/cookies-secure-flag")
                || ruleId.equalsIgnoreCase("java-security/cookies-http-only")) {
            return Type.INSECURE_COOKIE;
        }
        if (ruleId.equalsIgnoreCase("java-security/avoid-random")) {
            return Type.WEAK_RANDOMNESS;
        }
        if (ruleId.equalsIgnoreCase("java-security/sql-injection")) {
            return Type.SQL_INJECTION;
        }
        if (ruleId.equalsIgnoreCase("java-security/keygenerator-avoid-des")) {
            return Type.WEAK_CIPHER;
        }
        if (ruleId.equalsIgnoreCase("java-security/ldap-injection")) {
            return Type.LDAP_INJECTION;
        }
        if (ruleId.equalsIgnoreCase("java-security/command-injection")) {
            return Type.COMMAND_INJECTION;
        }
        if (ruleId.equalsIgnoreCase("java-security/weak-message-digest-md5")
                || ruleId.equalsIgnoreCase("java-security/weak-message-digest-sha1")) {
            return Type.WEAK_HASH;
        }
        if (ruleId.equalsIgnoreCase("java-security/xml-parsing-xxe-xpath")
                || ruleId.equalsIgnoreCase("java-security/tainted-xpath")) {
            return Type.XPATH_INJECTION;
        }
        if (ruleId.contains("java-security") && ruleId.contains("xss")) {
            return Type.XSS;
        }
        if (ruleId.contains("java-security")
                && ruleId.contains("trust")
                && ruleId.contains("bound")) {
            return Type.TRUST_BOUNDARY_VIOLATION;
        }
        if (ruleId.equalsIgnoreCase("java-security/path-traversal")) {
            return Type.PATH_TRAVERSAL;
        }
        return null;
    }

    /**
     * Try to get the CWE from the violation object in the SARIF report.
     *
     * @param violation the violation object from the SARIF report
     * @return the CWE if found, 0 otherwise
     */
    private int getCweFromProperties(JSONObject violation) {
        try {
            JSONObject properties = violation.getJSONObject("properties");
            JSONArray tags = properties.getJSONArray("tags");
            for (int k = 0; k < tags.length(); k++) {
                String s = tags.getString(k);
                if (s.contains("CWE:")) {
                    return Integer.parseInt(s.split(":")[1]);
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
                new TestSuiteResults("DatadogSast", false, TestSuiteResults.ToolType.SAST);

        tr.setTime(resultFile.file());

        for (int i = 0; i < runs.length(); i++) {
            JSONObject run = runs.getJSONObject(i);

            JSONObject driver = run.getJSONObject("tool").getJSONObject("driver");
            if (!driver.has("name")
                    || !driver.getString("name").equalsIgnoreCase(DATADOG_TOOL_NAME)) {
                continue;
            }

            tr.setToolVersion(driver.getString("version"));

            JSONArray results = run.getJSONArray("results");

            for (int j = 0; j < results.length(); j++) {
                JSONObject result = results.getJSONObject(j);
                String ruleId = result.getString("ruleId");
                TestCaseResult tcr = new TestCaseResult();

                // First, try to get the CWE based on the rule id. If it fails, try to get it from
                // the property of the violation.
                Type t = getTypeFromRuleId(ruleId);

                if (t != null) {
                    tcr.setCWE(t.number);
                    tcr.setCategory(t.id);
                } else {
                    continue;
                }

                if (tcr.getCWE() == 0) {
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
                tcr.setEvidence(result.getJSONObject("message").getString("text"));
                tr.put(tcr);
            }
        }
        return tr;
    }

    // Enumeration that contains the CWE and associated category.
    private enum Type {
        COMMAND_INJECTION(78),
        WEAK_HASH("crypto-bad-mac", 328),
        WEAK_CIPHER("crypto-bad-ciphers", 327),
        HEADER_INJECTION(113),
        INSECURE_COOKIE("cookie-flags-missing", 614),
        LDAP_INJECTION(90),
        PATH_TRAVERSAL(22),
        REFLECTION_INJECTION(0),
        SQL_INJECTION(89),
        STACKTRACE_LEAK(209),
        TRUST_BOUNDARY_VIOLATION(501),
        WEAK_RANDOMNESS("crypto-weak-randomness", 330),
        XPATH_INJECTION(643),
        XSS("reflected-xss", 79);

        private final int number;

        private final String id;

        Type(final int number) {
            this.number = number;
            id = name().toLowerCase().replaceAll("_", "-");
        }

        Type(final String id, final int number) {
            this.number = number;
            this.id = id;
        }
    }
}
