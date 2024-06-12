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
 * <p>This reader reads JSON reports from the Wapiti open source tool at:
 * https://wapiti.sourceforge.io/
 *
 * @author Sascha Knoop
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class WapitiJsonReader extends Reader {

    private Map<String, Integer> categoryCweMap;

    public WapitiJsonReader() {
        categoryCweMap = new HashMap<>();

        categoryCweMap.put("CRLF Injection", CweNumber.CRLF_INJECTION);
        categoryCweMap.put("Cross Site Request Forgery", CweNumber.CSRF);
        categoryCweMap.put("Command execution", CweNumber.COMMAND_INJECTION);
        categoryCweMap.put("Path Traversal", CweNumber.PATH_TRAVERSAL);
        categoryCweMap.put("Secure Flag cookie", CweNumber.INSECURE_COOKIE);
        categoryCweMap.put("Blind SQL Injection", CweNumber.SQL_INJECTION);
        categoryCweMap.put("SQL Injection", CweNumber.SQL_INJECTION);
        categoryCweMap.put("Cross Site Scripting", CweNumber.XSS);
        categoryCweMap.put("Stored Cross Site Scripting", CweNumber.XSS);
        categoryCweMap.put("Reflected Cross Site Scripting", CweNumber.XSS);
        categoryCweMap.put("XML External Entity", CweNumber.XXE);

        // Add others we don't currently care about, to make sure that all findings are considered,
        // and no new finding types are ignored
        // It is possible we'd care about some of these in the future
        categoryCweMap.put(
                "Content Security Policy Configuration", CweNumber.IMPROPER_UI_LAYER_RESTRICTION);
        categoryCweMap.put("Open Redirect", CweNumber.OPEN_REDIRECT);
        categoryCweMap.put("Server Side Request Forgery", CweNumber.SSRF);
        categoryCweMap.put("Backup file", CweNumber.DONTCARE);
        categoryCweMap.put("Fingerprint web application framework", CweNumber.DONTCARE);
        categoryCweMap.put("Fingerprint web server", CweNumber.DONTCARE);
        categoryCweMap.put("Htaccess Bypass", CweNumber.DONTCARE);
        categoryCweMap.put("HTTP Secure Headers", CweNumber.DONTCARE);
        categoryCweMap.put("HttpOnly Flag cookie", CweNumber.COOKIE_WITHOUT_HTTPONLY);
        categoryCweMap.put("Potentially dangerous file", CweNumber.DONTCARE);
        categoryCweMap.put("Weak credentials", CweNumber.DONTCARE);
        categoryCweMap.put("Spring4Shell", CweNumber.DONTCARE);
        categoryCweMap.put("Stored HTML Injection", CweNumber.DONTCARE);
        categoryCweMap.put("Subdomain takeover", CweNumber.DONTCARE);
        categoryCweMap.put("Unrestricted File Upload", CweNumber.DONTCARE);
        categoryCweMap.put("Unencrypted Channels", CweNumber.DONTCARE);
        categoryCweMap.put("Log4Shell", CweNumber.DONTCARE);
        categoryCweMap.put("HTML Injection", CweNumber.DONTCARE);
        categoryCweMap.put("TLS/SSL misconfigurations", CweNumber.DONTCARE);
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile
                    .json()
                    .getJSONObject("infos")
                    .getString("version")
                    .startsWith("Wapiti");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Wapiti", false, TestSuiteResults.ToolType.DAST);

        JSONObject vulnerabilities = resultFile.json().getJSONObject("vulnerabilities");

        for (Map.Entry<String, Integer> entry : categoryCweMap.entrySet()) {
            String category = entry.getKey();
            Integer cwe = entry.getValue();

            // The following gets all the vulnerabilities reported for the specified category
            // JSONArray arr = vulnerabilities.getJSONArray(category);
            JSONArray arr = (JSONArray) vulnerabilities.remove(category);

            // This then goes through all those results and adds every finding of that type reported
            // within a specified test case file
            if (arr != null) {
                for (int i = 0; i < arr.length(); i++) {
                    TestCaseResult tcr = parseTestCaseResult(arr.getJSONObject(i), cwe);
                    if (tcr != null) {
                        tr.put(tcr);
                    }
                }
            }
        }

        // Now check to see if there are extra vulnerability types not yet mapped
        if (!vulnerabilities.isEmpty()) {
            for (String key : vulnerabilities.keySet()) {
                System.out.println("Mapping missing for vulnerability category: " + key);
            }
        }

        tr.setToolVersion(readVersion(resultFile.json()));

        return tr;
    }

    private static TestCaseResult parseTestCaseResult(JSONObject finding, Integer cwe) {
        try {
            String filename = getFilenameFromFinding(finding);

            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();
                tcr.setNumber(testNumber(filename));
                tcr.setCWE(cwe);
                return tcr;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String getFilenameFromFinding(JSONObject finding) {
        return new File(finding.getString("path")).getName();
    }

    private static String readVersion(JSONObject json) {
        return json.getJSONObject("infos").getString("version").substring("Wapiti ".length());
    }
}
