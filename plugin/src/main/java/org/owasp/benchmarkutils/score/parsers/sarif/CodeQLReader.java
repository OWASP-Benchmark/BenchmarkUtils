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
 * @author Nipuna Weerasekara
 * @author Nicolas Couraud
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class CodeQLReader extends SarifReader {

    public CodeQLReader() {
        super("CodeQL", false, CweSourceType.TAG);
    }

    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case 94: // js/unsafe-dynamic-method-access & others - Improves the tool's score
                return CweNumber.COMMAND_INJECTION; // Command Injection
            case 335: // java/predictable-seed - Improves the tool's score
                return CweNumber.WEAK_RANDOM; // Weak Random
        }
        return cwe;
    }

    /**
     * Override setVersion to include the version number of the 'codeql/java-queries' ruleset with
     * the version of the tool. Since both the tool version and the ruleset version can seperately
     * affect the codeQL score.
     */
    @Override
    public void setVersion(ResultFile resultFile, TestSuiteResults testSuiteResults) {
        JSONObject driver = toolDriver(firstRun(resultFile));

        String version = "unknown";
        if (driver.has("semanticVersion")) {
            version = driver.getString("semanticVersion");
        } else if (driver.has("version")) {
            version = driver.getString("version");
        }

        // Search for codeql/java-queries ruleset version and add that to the tool version
        try {
            JSONArray extensions =
                    firstRun(resultFile).getJSONObject("tool").getJSONArray("extensions");

            for (int i = 0; i < extensions.length(); i++) {
                JSONObject extension = extensions.getJSONObject(i);
                String name = extension.getString("name");
                if ("codeql/java-queries".equals(name)) {
                    // looking for:
                    // "semanticVersion": "1.1.9+de325133c7a95d84489acdf5a6ced07886ff5c6d",
                    String rulesetVersion = extension.getString("semanticVersion");
                    rulesetVersion = rulesetVersion.substring(0, rulesetVersion.indexOf('+'));
                    version += "_w" + rulesetVersion + "rules";
                }
            }
        } catch (JSONException e) {
            // Do nothing it if can't be found.
        }

        testSuiteResults.setToolVersion(version);
    }
}
