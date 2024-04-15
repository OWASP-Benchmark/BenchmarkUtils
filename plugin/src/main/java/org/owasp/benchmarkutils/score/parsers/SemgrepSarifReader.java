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

import static java.lang.Integer.parseInt;

import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

public class SemgrepSarifReader extends SarifReader {

    @Override
    protected String expectedSarifToolName() {
        return "Semgrep OSS";
    }

    @Override
    protected boolean isCommercial() {
        return false;
    }

    @Override
    protected Map<String, Integer> ruleCweMappings(JSONArray rules) {
        Map<String, Integer> mappings = new HashMap<>();

        for (int i = 0; i < rules.length(); i++) {
            JSONObject rule = rules.getJSONObject(i);

            JSONArray tags = rule.getJSONObject("properties").getJSONArray("tags");

            for (int j = 0; j < tags.length(); j++) {
                String tag = tags.getString(j);

                if (tag.startsWith("CWE")) {
                    int cwe = parseInt(tag.split(":")[0].substring(4));

                    mappings.put(rule.getString("id"), cwe);
                }
            }
        }

        return mappings;
    }
}
