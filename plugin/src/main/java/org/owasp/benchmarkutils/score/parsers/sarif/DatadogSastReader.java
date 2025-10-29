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
package org.owasp.benchmarkutils.score.parsers.sarif;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.ResultFile;

/**
 * This reader is made for the datadog-static-analyzer available on <a
 * href="https://github.com/DataDog/datadog-static-analyzer">...</a>. It uses the SARIF file
 * produces by the tool.
 */
public class DatadogSastReader extends SarifReader {

    public DatadogSastReader() {
        super("datadog-static-analyzer", false, CweSourceType.CUSTOM);
    }

    @Override
    public String toolName(ResultFile resultFile) {
        try {
            String actualToolName =
                    resultFile
                            .json()
                            .getJSONArray("runs")
                            .getJSONObject(0)
                            .getJSONObject("tool")
                            .getJSONObject("driver")
                            .getString("name");

            if (actualToolName.equalsIgnoreCase("datadog-static-analyzer-llm")) {
                return "DatadogSastLlmFiltered";
            }
            return "DatadogSast";
        } catch (Exception e) {
            return "DatadogSast";
        }
    }

    @Override
    public Map<String, Integer> customRuleCweMappings(JSONObject tool) {
        // Start with tag-based mappings as the base
        Map<String, Integer> mappings = ruleCweMappingsByTag(tool);

        // Override with custom mappings for specific rules
        // SQL Injection - CWE-89
        addRuleMapping(mappings, "sql-injection", 89);
        addRuleMapping(mappings, "variable-sql-statement-injection", 89);

        // Command Injection - CWE-78
        addRuleMapping(mappings, "command-injection", 78);
        addRuleMapping(mappings, "shell-injection", 78);
        addRuleMapping(mappings, "asyncio-subprocess-create-shell", 78);
        addRuleMapping(mappings, "asyncio-subprocess-exec", 78);
        addRuleMapping(mappings, "os-spawn", 78);
        addRuleMapping(mappings, "os-system", 78);
        addRuleMapping(mappings, "subprocess-shell-true", 78);

        // XSS - CWE-79
        addRuleMapping(mappings, "xss-protection", 79);
        addRuleMapping(mappings, "html-string-from-parameters", 79);
        addRuleMapping(mappings, "responsewriter-no-fprintf", 79);
        addRuleMapping(mappings, "unescape-template-data-js", 79);
        addRuleMapping(mappings, "jinja-autoescape", 79);

        // LDAP Injection - CWE-90
        addRuleMapping(mappings, "ldap-injection", 90);

        // Path Traversal - CWE-22
        addRuleMapping(mappings, "path-traversal", 22);
        addRuleMapping(mappings, "taint-url", 22);

        // Weak Cipher - CWE-327
        addRuleMapping(mappings, "keygenerator-avoid-des", 327);
        addRuleMapping(mappings, "import-des", 327);
        addRuleMapping(mappings, "ssl-v3-insecure", 327);
        addRuleMapping(mappings, "jwt-algorithm", 327);
        addRuleMapping(mappings, "tls-cipher", 327);
        addRuleMapping(mappings, "weak-cipher", 327);
        addRuleMapping(mappings, "use-standard-crypto", 327);
        addRuleMapping(mappings, "weak-ssl-protocols", 327);

        // Weak Hash - CWE-328
        addRuleMapping(mappings, "weak-message-digest-md5", 328);
        addRuleMapping(mappings, "weak-message-digest-sha1", 328);
        addRuleMapping(mappings, "import-md5", 328);
        addRuleMapping(mappings, "import-sha1", 328);
        addRuleMapping(mappings, "weak-hash-algorithms", 328);
        addRuleMapping(mappings, "insecure-hash-functions", 328);

        // Weak Randomness - CWE-330
        addRuleMapping(mappings, "avoid-random", 330);
        addRuleMapping(mappings, "math-rand-insecure", 330);
        addRuleMapping(mappings, "no-pseudo-random", 330);

        // Trust Boundary Violation - CWE-501
        addRuleMapping(mappings, "trust-boundaries", 501);

        // Insecure Cookie - CWE-614
        addRuleMapping(mappings, "cookies-secure-flag", 614);
        addRuleMapping(mappings, "cookie-secure-flag", 614);
        addRuleMapping(mappings, "session-secure", 614);
        addRuleMapping(mappings, "cookie-secure", 614);

        // XPath Injection - CWE-643
        addRuleMapping(mappings, "xml-parsing-xxe-xpath", 643);
        addRuleMapping(mappings, "tainted-xpath", 643);
        addRuleMapping(mappings, "xpath-injection", 643);

        return mappings;
    }

    private Map<String, Integer> ruleCweMappingsByTag(JSONObject tool) {
        Map<String, Integer> mappings = new HashMap<>();

        Set<JSONObject> rules = extractRulesFrom(tool);
        for (JSONObject rule : rules) {
            if (rule.has("properties") && rule.getJSONObject("properties").has("tags")) {
                JSONArray tags = rule.getJSONObject("properties").getJSONArray("tags");

                for (int j = 0; j < tags.length(); j++) {
                    String tag = tags.getString(j).toLowerCase();

                    // only take first CWE id for rule
                    if (tag.contains("cwe") && !mappings.containsKey(rule.getString("id"))) {
                        mappings.put(rule.getString("id"), mapCwe(extractCwe(tag)));
                    }
                }
            }
        }

        return mappings;
    }

    // Use the same extractRulesFrom method as the parent class
    private static Set<JSONObject> extractRulesFrom(JSONObject tool) {
        HashSet<JSONObject> toolRules = new HashSet<>();

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

    private void addRuleMapping(Map<String, Integer> mappings, String ruleName, int cwe) {
        mappings.put("java-security/" + ruleName, cwe);
        mappings.put("go-security/" + ruleName, cwe);
        mappings.put("python-security/" + ruleName, cwe);
        mappings.put("csharp-security/" + ruleName, cwe);
    }
}
