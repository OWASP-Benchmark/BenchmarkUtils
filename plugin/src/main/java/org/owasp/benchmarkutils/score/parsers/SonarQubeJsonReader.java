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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Dave Wichers
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SonarQubeJsonReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        // SonarQube has two different JSON formats, one for standard issues and
        // another for 'hotspots' which are security issues. Both are handled by
        // the same parser for SonarQube.
        return resultFile.isJson()
                && (resultFile.json().has("hotspots") || resultFile.json().has("issues"))
                && !resultFile.json().has("type"); // Ignore Coverity results
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("SonarQube", false, TestSuiteResults.ToolType.SAST);

        // If the filename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml),
        // set the compute time on the score card.
        tr.setTime(resultFile.file());

        parseIssues(tr, resultFile.json());
        parseHotspots(tr, resultFile.json());

        return tr;
    }

    private void parseHotspots(TestSuiteResults tr, JSONObject obj) {
        parseResults(tr, obj, true);
    }

    private void parseIssues(TestSuiteResults tr, JSONObject obj) {
        parseResults(tr, obj, false);
    }

    private void parseResults(TestSuiteResults tr, JSONObject obj, boolean isHotspots) {
        String key = isHotspots ? "hotspots" : "issues";

        if (!obj.has(key)) {
            return;
        }

        JSONArray arr = obj.getJSONArray(key);
        int numIssues = arr.length();

        for (int i = 0; i < numIssues; i++) {
            TestCaseResult tcr =
                    (isHotspots
                            ? parseSonarQubeHotSpotIssue(arr.getJSONObject(i))
                            : parseSonarQubeQualityIssue(arr.getJSONObject(i)));
            if (tcr != null) {
                if (tcr.getNumber() == 0) {
                    System.out.println(
                            "SQ Error: JSON object parsed with isHotspot key: '"
                                    + key
                                    + "' to test case num 0: "
                                    + arr.getJSONObject(i));
                }
                tr.put(tcr);
            }
        }
    }

    /**
     * -- Example of Quality Issue JSON object VULNERABILITY", "tags":["cwe","owasp-a2","owasp-a6"],
     * "component":"org.owasp:benchmark:src\/main\/java\/org\/owasp\/benchmark\/testcode\/BenchmarkTest02710.java",
     * "flows":[], "textRange":{"endLine":63,"endOffset":34,"startOffset":28,"startLine":63},
     * "debt":"5min","key":"AVvEV4Ovf4saFi7UxJTq","status":"OPEN"},
     *
     * <p>{"severity":"CRITICAL", "updateDate":"2017-05-01T10:07:01-0400", "componentId":2777,
     * "line":55,"author":"", "rule":"squid:S2076", "project":"org.owasp:benchmark",
     * "effort":"30min", "message":"Make sure \"cmd\" is properly sanitized before use in this OS
     * command.", "creationDate":"2017-05-01T10:07:01-0400", "type":"VULNERABILITY",
     * "tags":["cwe","owasp-a1","sans-top25-insecure"],
     * "component":"org.owasp:benchmark:src\/main\/java\/org\/owasp\/benchmark\/testcode\/BenchmarkTest02713.java",
     * "flows":[],"textRange":{"endLine":55,"endOffset":26,"startOffset":22,"startLine":55},
     * "debt":"30min","key":"AVvEV4Oyf4saFi7UxJTr","status":"OPEN"},
     */

    // Quality Issues are normal SonarQube findings that are mostly not relevant to security
    // However, there are a small number of security issues that do show up this way so we have
    // to support both
    /**
     * Parse the SonarQube Quality results to see if there is a finding in Benchmark test case.
     *
     * @param finding The JSON text of the SonarQube Quality finding.
     * @return Returns a TestCaseResult if there is a finding in a Benchmark testcase file,
     *     otherwise it returns null.
     */
    private TestCaseResult parseSonarQubeQualityIssue(JSONObject finding) {
        try {
            String filename = finding.getString("component");
            filename = filename.replaceAll("\\\\", "/");
            filename = filename.substring(filename.lastIndexOf('/'));
            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();
                tcr.setNumber(testNumber(filename));
                String rule = finding.getString("rule");
                String squid = rule.substring(rule.indexOf(":") + 1);
                if (squid == null || squid.equals("none")) {
                    return null;
                }
                int cwe = SonarQubeReader.cweLookup(squid);
                tcr.setCWE(cwe);
                tcr.setCategory(finding.getJSONArray("tags").toString());
                tcr.setEvidence(finding.getString("message"));
                return tcr;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // Finding not in a test case
    }

    // The parseSonarQubeQualityIssue() method above relies on the SQUID # mapping method in
    // SonarQubeReader.cweLookup()

    /**
     * -- Example of HotSpot Issue JSON object "hotspots": [ { "key": "AXYEidyZsoEy1bftafT5",
     * "component":
     * "owasp-benchmark-sonarce:src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00008.java",
     * "project": "owasp-benchmark-sonarce", "securityCategory": "sql-injection",
     * "vulnerabilityProbability": "HIGH", "status": "TO_REVIEW", "line": 58, "message": "Ensure
     * that string concatenation is required and safe for this SQL query.", "author":
     * "dwichers@gmail.com", "creationDate": "2015-08-26T05:13:42+0200", "updateDate":
     * "2020-11-26T12:53:38+0100" },
     */

    // Hotspot Issues are SonarQube security findings.
    /**
     * Parse the SonarQube HotSpot results to see if there is a finding in Benchmark test case.
     *
     * @param finding The JSON text of the SonarQube HotSpot finding.
     * @return Returns a TestCaseResult if there is a finding in a Benchmark testcase file,
     *     otherwise it returns null.
     */
    private TestCaseResult parseSonarQubeHotSpotIssue(JSONObject finding) {
        try {
            String filename = finding.getString("component");
            filename =
                    filename.replaceAll(
                            "\\\\", "/"); // In case there are \ instead of / in the path
            filename = filename.substring(filename.lastIndexOf('/'));
            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();
                tcr.setNumber(testNumber(filename));
                String secCat = finding.getString("securityCategory");
                if (secCat == null || secCat.equals("none")) {
                    return null;
                }
                int cwe = securityCategoryCWELookup(secCat, finding.getString("message"));
                tcr.setCWE(cwe);
                tcr.setCategory(secCat);
                tcr.setEvidence(
                        "vulnerabilityProbability: "
                                + finding.getString("vulnerabilityProbability"));
                return tcr;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null; // Finding not in a test case
    }

    /*
     * Some of these findings are badly mapped. For example:
     *      "securityCategory": "xss",
     *      "message": "Make sure creating this cookie without the \"HttpOnly\" flag is safe.",
     *  While HttpOnly is a feature to help defend against XSS, it should really be mapped to
     *  CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag. So we use the 'message' description
     *            in some findings to move such issues to the 'right' CWE.
     *  As such, we specifically look at the message in some cases to fix the mapping.
     */
    public int securityCategoryCWELookup(String secCat, String message) {
        // Not sure where to look up all the possible security categories in SonarQube, but the
        // mappings seem obvious enough.

        // Given their horrible mapping scheme, we check each message to detect whether there might
        // be a new 'message' mapped to an existing CWE (that might be wrong).
        if (!("Make sure that using this pseudorandom number generator is safe here."
                        .equals(message)
                || "Ensure that string concatenation is required and safe for this SQL query."
                        .equals(message)
                || "Make sure using a dynamically formatted SQL query is safe here.".equals(message)
                || "Make sure creating this cookie without the \"secure\" flag is safe here."
                        .equals(message)
                || "Make sure that hashing data is safe here.".equals(message)
                || "Make sure this weak hash algorithm is not used in a sensitive context here."
                        .equals(message)
                || "Make sure creating this cookie without the \"HttpOnly\" flag is safe."
                        .equals(message))) {
            System.out.println(
                    "WARN: Found new SonarQube HotSpot rule not seen before. Category: "
                            + secCat
                            + " with message: '"
                            + message
                            + "'");
        }

        switch (secCat) {
            case "sql-injection":
                // "Ensure that string concatenation is required and safe for this SQL query."
                return CweNumber.SQL_INJECTION;
            case "insecure-conf":
                // "Make sure creating this cookie without the \"secure\" flag is safe here."
                return CweNumber.INSECURE_COOKIE;
            case "xss":
                {
                    // "Make sure creating this cookie without the \"HttpOnly\" flag is safe."
                    if (message != null && message.contains("HttpOnly"))
                        return CweNumber.COOKIE_WITHOUT_HTTPONLY;
                    else return CweNumber.XSS; // Actual XSS CWE
                }
            case "weak-cryptography":
                {
                    // "Make sure that using this pseudorandom number generator is safe here."
                    // or "Make sure that hashing data is safe here."
                    if (message != null) {
                        if (message.contains("pseudorandom")) return CweNumber.WEAK_RANDOM;
                        if (message.contains("hashing")) return CweNumber.WEAK_HASH_ALGO;
                        // Deliberately fall through. The 'others' check will also fail since the
                        // message check is very specific. So it will drop through to the default:
                        // case.
                    } else return CweNumber.WEAK_CRYPTO_ALGO; // Actual Weak Crypto CWE
                }
            case "others":
                {
                    if (message != null
                            && message.equals(
                                    "Make sure this weak hash algorithm is not used in a sensitive context here.")) {
                        return CweNumber.WEAK_HASH_ALGO;
                    }
                    // Otherwise deliberately drop through to default error message.
                }
            default:
                System.out.println(
                        "WARN: Failed to translate SonarQube security category: '"
                                + secCat
                                + "' with message: '"
                                + message
                                + "'");
        }

        return -1;
    }

    // This parser relies on the SQUID # mapping method in SonarQubeReader.cweLookup()
}
