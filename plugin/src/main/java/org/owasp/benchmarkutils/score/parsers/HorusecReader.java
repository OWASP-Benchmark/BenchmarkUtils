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
 * <p>This reader reads JSON reports from the Horusec open source tool at:
 * https://github.com/ZupIT/horusec
 *
 * @author Sascha Knoop
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.File;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class HorusecReader extends Reader {

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.isJson()
                    && resultFile
                            .json()
                            .getJSONArray("analysisVulnerabilities")
                            .getJSONObject(0)
                            .getJSONObject("vulnerabilities")
                            .has("securityTool");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONObject json = resultFile.json();

        TestSuiteResults tr =
                new TestSuiteResults("Horusec", false, TestSuiteResults.ToolType.SAST);

        JSONArray arr = json.getJSONArray("analysisVulnerabilities");

        for (int i = 0; i < arr.length(); i++) {
            TestCaseResult tcr = parseTestCaseResult(arr.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        tr.setToolVersion(readVersion(json));
        tr.setTime(calculateTime(json.getString("createdAt"), json.getString("finishedAt")));

        return tr;
    }

    private TestCaseResult parseTestCaseResult(JSONObject finding) {
        try {
            JSONObject vuln = finding.getJSONObject("vulnerabilities");

            String filename = filename(vuln);

            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();
                tcr.setNumber(testNumber(filename));
                tcr.setCWE(figureCwe(vuln));
                return tcr;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private int figureCwe(JSONObject vuln) {
        String details = vuln.getString("details");

        String cwe = fetchCweFromDetails(details);

        if (cwe == null) {
            cwe = guessCwe(details);
        }

        switch (cwe) {
            case "79":
                return CweNumber.XSS;
            case "89":
                return CweNumber.SQL_INJECTION;
            case "326":
            case "327":
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "328":
                return CweNumber.WEAK_HASH_ALGO;
            case "329":
                return CweNumber.STATIC_CRYPTO_INIT;
            case "330":
                return CweNumber.WEAK_RANDOM;
            case "502":
                if (category(details).equals("LDAP deserialization should be disabled")) {
                    return CweNumber.LDAP_INJECTION;
                }

                return CweNumber.INSECURE_DESERIALIZATION;
            case "611":
                return CweNumber.XXE;
            case "614":
                return CweNumber.INSECURE_COOKIE;
            case "643":
                return CweNumber.XPATH_INJECTION;
            case "649":
                return CweNumber.OBFUSCATION;
            default:
                System.out.println("WARN: Horusec reported CWE not yet mapped: " + cwe);
                return Integer.parseInt(cwe);
        }
    }

    private String fetchCweFromDetails(String details) {
        if (!details.contains("CWE")) {
            return null;
        }

        String cweTmp = details.substring(details.indexOf("CWE-") + 4);

        return cweTmp.substring(0, cweTmp.indexOf(' '));
    }

    private String guessCwe(String details) {
        switch (category(details)) {
            case "Java Crypto import":
            case "DES is considered deprecated. AES is the recommended cipher.":
            case "DES is considered deprecated. AES is the recommended cipher. Upgrade to use AES. See https://www.nist.gov/news-events/news/2005/06/nist-withdraws-outdated-data-encryption-standard for more information.":
                return "327";
            case "Weak block mode for Cryptographic Hash Function":
            case "Message Digest":
                return "328";
            case "Cookie without the HttpOnly flag":
                return "614";
            case "Base64 Encode":
                return "649";
            default:
                throw new RuntimeException(details);
        }
    }

    private String category(String details) {
        return details.split("\n")[0].trim();
    }

    private String filename(JSONObject vuln) {
        return new File(vuln.getString("file")).getName();
    }

    private String calculateTime(String createdAt, String finishedAt) {
        try {
            long passedMilliseconds = unixMilliseconds(finishedAt) - unixMilliseconds(createdAt);
            return TestSuiteResults.formatTime(passedMilliseconds);
        } catch (Exception e) {
            e.printStackTrace();
            return "Unknown";
        }
    }

    private long unixMilliseconds(String createdAt) throws ParseException {
        return sdf.parse(trimAfterDot(createdAt)).getTime();
    }

    private String trimAfterDot(String date) {
        return date.substring(0, date.indexOf('.'));
    }

    private String readVersion(JSONObject json) {
        if (json.has("version")) {
            return json.getString("version");
        } else {
            return "0.0.0";
        }
    }
}
