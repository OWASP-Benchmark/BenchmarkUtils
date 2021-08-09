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
 * @created 2015
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

public class ShiftLeftNGSASTReaderJSON extends Reader {

    public TestSuiteResults parse(File f, Node root) throws Exception {

        String content = new String(Files.readAllBytes(Paths.get(f.getPath())));
        JSONObject obj = new JSONObject(content);

        TestSuiteResults tr =
                new TestSuiteResults("ShiftLeft NGSAST", true, TestSuiteResults.ToolType.SAST);

        // None of this metadata is provided
        //        String version = getAttributeValue( "ShiftLeftVersion", root );
        //        tr.setToolVersion( version );

        //        String time = getAttributeValue("ScanTime", root);
        //        tr.setTime( time );

        JSONArray children = obj.getJSONArray("");
        for (int i = 0; i < children.length(); i++) {
            try {
                TestCaseResult tcr = parseNGSASTVulnerability(children.getJSONObject(i));
                if (tcr != null) {
                    tr.put(tcr);
                }
            } catch (Exception e) {
                System.out.println(">> Error detected. Attempting to continue parsing");
                e.printStackTrace();
            }
        }
        return tr;
    }

    private TestCaseResult parseNGSASTVulnerability(JSONObject finding) {

        /* "title: "SQL Injection: HTTP data to SQL database via `request` in `BenchmarkTest00774.doPost`",
           ...
           "tags": [
             {
               "key": "category",
               "value": "SQL Injection",
               "shiftleft_managed": true
             },
             ...
             {
               "key": "cwe_category",
               "value": "89",
               "shiftleft_managed": true
             },
        */
        String title = finding.getString("title");
        System.out.println("NGSAST finding title is: " + title);

        int testCaseNameLoc = title.indexOf(BenchmarkScore.TESTCASENAME);

        if (testCaseNameLoc > 0) {
            // Get the test case number
            TestCaseResult tcr = new TestCaseResult();

            int testCaseNumLoc = testCaseNameLoc + BenchmarkScore.TESTCASENAME.length();
            String testno = title.substring(testCaseNumLoc, testCaseNumLoc + 5);
            try {
                tcr.setNumber(Integer.parseInt(testno));
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }

            // First get all the tags, then find the CWE entry in those tags
            JSONArray tags = finding.getJSONArray("tags");

            for (int i = 0; i < tags.length(); i++) {

                if ("cwe_category".equals(tags.getJSONObject(i).getString("key"))) {
                    String cweNum = tags.getJSONObject(i).getString("value");
                    tcr.setCWE(Integer.parseInt(cweNum));
                    return tcr;
                }
            }
        }
        return null;
    }

    // Needed??
    private int translate(int cwe) {
        switch (cwe) {
            case 77:
                return 78; // command injection
            case 36:
                return 22; // path traversal
            case 23:
                return 22; // path traversal
            case 338:
                return 330; // weak random
        }
        return cwe;
    }
}
