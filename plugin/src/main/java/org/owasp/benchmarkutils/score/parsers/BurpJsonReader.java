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
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class BurpJsonReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson() && resultFile.json().has("issue_events");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONArray arr = resultFile.json().getJSONArray("issue_events");

        TestSuiteResults tr =
                new TestSuiteResults("Burp Suite Enterprise", true, TestSuiteResults.ToolType.DAST);

        // If the filename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml),
        // set the compute time on the score card.
        tr.setTime(resultFile.file());

        int numIssues = arr.length();
        for (int i = 0; i < numIssues; i++) {
            TestCaseResult tcr = parseBurpJSONFinding(arr.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    /**
     * "issue_events": [ <-- the array that contains all the findings. 1 example below { "id": "94",
     * "type": "issue_found", "issue": { "name": "TLS certificate", "type_index": 16777472,
     * "serial_number": "3879069528566581248", "origin": "https://localhost:8443", "path": "/",
     * "severity": "medium", "confidence": "certain", "description": "The following problems were
     * identified with the server's TLS certificate:
     *
     * <ul>
     *   <li>The server's certificate is not valid for the server's hostname.
     *   <li>The server's certificate is not trusted.
     *   <li>The server's certificate has expired.
     * </ul>
     *
     * <b>Note:</b> Burp relies on the Java trust store to determine whether certificates are
     * trusted. The Java trust store does not include every root CA certificate that is included
     * within browser trust stores. Burp might incorrectly repo rt that a certificate is not
     * trusted, if a valid root CA certificate is being used that is not included in the Java trust
     * store.<br>
     * <br>
     * The server presented the following certificate:<br>
     * <br>
     *
     * <table>
     * <tr><td><b>Issued to:</b>&nbsp;&nbsp;</td><td>OWASP Benchmark</td></tr><tr><td><b>Issued by:</b>&nbsp;&nbsp;</td><td>OWASP Benchmark</td></tr><tr><td><b>Valid from:</b>&nbsp;&nbsp;</td><td>Mon Sep 28 19:39:43 CEST 2015</td></tr><tr><td><b>Valid to:</b>&nbsp;&nbsp;</td><td>Sun Dec 27 18:39:43 CET 2015</td></tr>
     * </table>
     *
     * <p>", "caption": "/", "evidence": [], "internal_data":
     * "eyJmbGFncyI6MTQsInZhcmlhbnQiOjAsImlzc3VlX2RldGFpbHNfbWFwIjp7IjM0Ijoip09XQVNQIEJlbmNobWFya6dPV0FTUCBCZW5jaG1hcmunTW9uIFNlcCAyOCAxOTozOTo0MyBDRVNUIDIwMTWnU3VuIERlYyAyNyAxODozOTo0MyBDRVQgMjAxNacxNKcifX0="
     * } }, ...
     */
    private TestCaseResult parseBurpJSONFinding(JSONObject finding) {
        try {
            TestCaseResult tcr = new TestCaseResult();
            String filename = null;

            JSONObject issue = finding.getJSONObject("issue");
            filename = issue.getString("path");

            filename = filename.substring(filename.lastIndexOf('/') + 1);
            filename =
                    filename.split("\\.")[
                            0]; // If there is any extension on the filename, remove it
            if (filename.startsWith(BenchmarkScore.TESTCASENAME)) {
                tcr.setNumber(testNumber(filename));
                int rule = issue.getInt("type_index");
                int cwe = BurpReader.cweLookup(new Integer(rule).toString());
                tcr.setCWE(cwe);
                // tcr.setEvidence( issue.getString("description") ); // Sometimes descriptions
                // aren't provided, so comment out.
                return tcr;
            }

        } catch (JSONException e) {
            e.printStackTrace();
        }
        return null;
    }

    // This parser relies on the Burp rule # mapping method in BurpReader.cweLookup()
}
