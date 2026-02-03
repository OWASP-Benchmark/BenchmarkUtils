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
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.parsers.SemgrepReader;

public class EndorSarifReader extends SarifReader {

    public EndorSarifReader() {
        super("", false, CweSourceType.TAG);
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            if (!resultFile.isJson()) {
                return false;
            }

            String fileName = resultFile.file().getName().toLowerCase();
            String toolName = toolDriver(firstRun(resultFile)).optString("name", "");
            String normalized = toolName.toLowerCase();

            // Prefer matching on SARIF tool name, since we may have multiple Endor variants.
            // Filename is used as a fallback/guard.
            return normalized.startsWith("endorctl")
                    || normalized.contains("endor")
                    || fileName.contains("endor");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String toolName(ResultFile resultFile) {
        try {
            String toolName = toolDriver(firstRun(resultFile)).optString("name", "");
            String normalized = toolName.toLowerCase();

            if (normalized.startsWith("endorctl")) {
                String suffix = toolName.replaceFirst("(?i)^endorctl-?", "").trim();
                if (!suffix.isEmpty()) {
                    return "Endor " + suffix;
                }
            }
        } catch (Exception ignored) {
        }

        return "Endor";
    }

    @Override
    public org.owasp.benchmarkutils.score.TestSuiteResults parse(ResultFile resultFile)
            throws Exception {
        // Endor-specific filtering: remove findings explicitly marked as false positives in the
        // explanation field so they don't affect scorecard statistics.
        try {
            JSONObject root = resultFile.json();
            JSONArray runs = root.optJSONArray("runs");
            if (runs != null) {
                for (int i = 0; i < runs.length(); i++) {
                    JSONObject run = runs.optJSONObject(i);
                    if (run == null) {
                        continue;
                    }

                    JSONArray results = run.optJSONArray("results");
                    if (results == null) {
                        continue;
                    }

                    for (int j = results.length() - 1; j >= 0; j--) {
                        JSONObject result = results.optJSONObject(j);
                        if (isFalsePositive(result)) {
                            results.remove(j);
                        }
                    }
                }
            }
        } catch (Exception ignored) {
            // If filtering fails for any reason, fall back to scoring all results.
        }

        return super.parse(resultFile);
    }

    private static boolean isFalsePositive(JSONObject result) {
        if (result == null) {
            return false;
        }

        JSONObject properties = result.optJSONObject("properties");
        if (properties == null) {
            return false;
        }

        String explanation = properties.optString("explanation", "");
        return explanation.toLowerCase().contains("false positive");
    }

    @Override
    public int mapCwe(int cwe) {
        return SemgrepReader.translate(cwe);
    }
}
