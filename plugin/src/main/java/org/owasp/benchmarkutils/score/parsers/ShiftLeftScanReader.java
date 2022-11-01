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
 * <p>This reader reads JSON reports from the open source version of ShiftLeft Scan at:
 * https://github.com/ShiftLeftSecurity/sast-scan. ShiftLeft has a commercial version of this tool
 * as well.
 *
 * @author Sascha Knoop
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.File;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ShiftLeftScanReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.content().contains("@ShiftLeft/sast-scan");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONObject javaSourceAnalyzer = new JSONObject(resultFile.line(0));
        JSONObject classFileAnalyzer = new JSONObject(resultFile.line(1));

        // false indicates this is an open source/free tool.
        TestSuiteResults tr =
                new TestSuiteResults("ShiftLeft Scan", false, TestSuiteResults.ToolType.SAST);

        parseAndAddResults(tr, javaSourceAnalyzer);
        parseAndAddResults(tr, classFileAnalyzer);

        tr.setToolVersion(readVersion(javaSourceAnalyzer));

        return tr;
    }

    private String readVersion(JSONObject javaSourceAnalyzer) {
        return javaSourceAnalyzer
                .getJSONObject("tool")
                .getJSONObject("driver")
                .getString("version")
                .replace("-scan", "");
    }

    private void parseAndAddResults(TestSuiteResults tr, JSONObject analyzerResults) {
        JSONArray arr = analyzerResults.getJSONArray("results");

        for (int i = 0; i < arr.length(); i++) {
            TestCaseResult tcr = parseTestCaseResult(arr.getJSONObject(i));

            if (tcr != null) {
                tr.put(tcr);
            }
        }
    }

    private TestCaseResult parseTestCaseResult(JSONObject finding) {
        try {
            String filename = filename(finding);

            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();

                tcr.setNumber(testNumber(filename));
                tcr.setCWE(cweNumber(finding));

                return tcr;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private String filename(JSONObject finding) {
        JSONArray locations = finding.getJSONArray("locations");

        if (locations.length() != 1) {
            throw new RuntimeException(finding.toString());
        }

        return new File(
                        locations
                                .getJSONObject(0)
                                .getJSONObject("physicalLocation")
                                .getJSONObject("artifactLocation")
                                .getString("uri"))
                .getName();
    }

    private CweNumber cweNumber(JSONObject finding) {
        String ruleId = finding.getString("ruleId");

        switch (ruleId) {
            case "PATH_TRAVERSAL_IN":
            case "PATH_TRAVERSAL_OUT":
            case "PT_RELATIVE_PATH_TRAVERSAL":
            case "PT_ABSOLUTE_PATH_TRAVERSAL":
                return CweNumber.PATH_TRAVERSAL;
            case "COMMAND_INJECTION":
                return CweNumber.OS_COMMAND_INJECTION;
            case "HTTP_RESPONSE_SPLITTING":
                return CweNumber.HTTP_RESPONSE_SPLITTING;
            case "XSS_SERVLET":
            case "HRS_REQUEST_PARAMETER_TO_COOKIE":
            case "XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER":
                return CweNumber.XSS;
            case "SQL_INJECTION_JDBC":
            case "SQL_INJECTION_SPRING_JDBC":
            case "SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE":
            case "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING":
                return CweNumber.SQL_INJECTION;
            case "LDAP_INJECTION":
                return CweNumber.LDAP_INJECTION;
            case "PADDING_ORACLE":
                // FIXME: shouldn't this be 463?
                return CweNumber.ERROR_MESSAGE_WITH_SENSITIVE_INFO;
            case "DES_USAGE":
            case "CIPHER_INTEGRITY":
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "WEAK_MESSAGE_DIGEST_MD5":
            case "WEAK_MESSAGE_DIGEST_SHA1":
                return CweNumber.WEAK_HASH_ALGO;
            case "STATIC_IV":
                return CweNumber.STATIC_CRYPTO_INIT;
            case "PREDICTABLE_RANDOM":
                return CweNumber.WEAK_RANDOM;
            case "TRUST_BOUNDARY_VIOLATION":
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case "HTTPONLY_COOKIE":
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;
            case "INSECURE_COOKIE":
                return CweNumber.INSECURE_COOKIE;
            case "XPATH_INJECTION":
                return CweNumber.XPATH_INJECTION;

            default:
                System.out.println(
                        "INFO: Found following ruleId which we haven't seen before: " + ruleId);
                return CweNumber.DONTCARE;
        }
    }
}
