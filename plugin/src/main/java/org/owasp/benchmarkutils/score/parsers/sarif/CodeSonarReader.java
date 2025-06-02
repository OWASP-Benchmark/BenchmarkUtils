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
 * @author Dave Wichers
 * @created 2025
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import static java.lang.Integer.parseInt;

import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CodeSonarReader extends SarifReader {

    // Setting CweSourceType.CUSTOM causes the customRuleCweMappings() method to be invoked
    public CodeSonarReader() {
        super("CodeSonar", false, CweSourceType.CUSTOM);
    }

    @Override
    public Map<String, Integer> customRuleCweMappings(JSONObject tool) {
        Map<String, Integer> mappings = new HashMap<>();

        JSONArray rules = tool.getJSONObject("driver").getJSONArray("rules");

        for (int j = 0; j < rules.length(); j++) {
            try {
                JSONObject rule = rules.getJSONObject(j);

                String cwetext = rule.getJSONObject("help").getString("text");

                // only take first CWE id for rule
                String ruleID = rule.getString("id");

                // DRW TODO: Might be better to manually map rules rather than grab the 1st CWE, as
                // manually mapping is more precise

                if (cwetext.contains("CWE:") && !mappings.containsKey(ruleID)) {
                    // Find and trim off everything before "CWE:"
                    int startIndex = cwetext.indexOf("CWE:") + "CWE:".length();
                    cwetext = cwetext.substring(startIndex);
                    // Find and trim off everything after trailing space or end of string
                    int endIndex = cwetext.indexOf(' ');
                    if (endIndex == -1) endIndex = cwetext.length();

                    int CWENum = parseInt(cwetext.substring(0, endIndex));

                    mappings.put(ruleID, CWENum);
                }
            } catch (JSONException e) {
                System.err.println(
                        "WARNING: " + e.getMessage() + " for rule: " + rules.getJSONObject(j));
            }
        }

        return mappings;
    }
}
