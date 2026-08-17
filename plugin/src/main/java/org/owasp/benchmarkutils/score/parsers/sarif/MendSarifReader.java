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
 * @author Jan Kühl
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class MendSarifReader extends SarifReader {

    public MendSarifReader() {
        super("mend.sast.", true, CweSourceType.CUSTOM);
    }

    @Override
    public String toolName(ResultFile resultFile) {
        return "Mend SAST";
    }

    /**
     * Mend's SARIF driver reports its version as a descriptive, comma-separated string per language
     * (e.g. {@code "26.6.1.2 (Java*)"}).
     */
    @Override
    public void setVersion(ResultFile resultFile, TestSuiteResults testSuiteResults) {
        super.setVersion(resultFile, testSuiteResults);

        String version = testSuiteResults.getToolVersion();

        if (version == null) {
            return;
        }

        Matcher matcher = Pattern.compile("^[0-9][0-9.]*").matcher(version);

        if (matcher.find()) {
            testSuiteResults.setToolVersion(matcher.group());
        }
    }

    @Override
    public Map<String, Integer> customRuleCweMappings(JSONObject tool) {
        Map<String, Integer> ruleCweMap = new HashMap<>();

        JSONArray rules = tool.getJSONObject("driver").getJSONArray("rules");

        for (int i = 0; i < rules.length(); i++) {
            try {
                JSONObject rule = rules.getJSONObject(i);

                // Mend rules don't carry a CWE tag or field in a SARIF report.
                // The CWE is only present as the trailing number of each rule's helpUri
                // (e.g. https://cwe.mitre.org/data/definitions/78.html),
                // so CWEs are scraped from there.
                int cwe = mapCwe(extractCwe(rule.getString("helpUri")));

                ruleCweMap.put(rule.getString("id"), cwe);
            } catch (JSONException e) {
                // Skip rules without a helpUri-based CWE reference.
            }
        }

        return ruleCweMap;
    }

    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case 338:
                return CweNumber.WEAK_RANDOM;
            case 1004:
                return CweNumber.INSECURE_COOKIE;
            default:
                return cwe;
        }
    }
}
