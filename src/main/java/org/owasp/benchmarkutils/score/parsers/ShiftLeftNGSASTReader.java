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
import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

public class ShiftLeftNGSASTReader extends Reader {

    public TestSuiteResults parse(File f, Node root) throws Exception {

        TestSuiteResults tr =
                new TestSuiteResults("ShiftLeft NGSAST", true, TestSuiteResults.ToolType.SAST);

        // None of this metadata is provided
        //        String version = getAttributeValue( "ShiftLeftVersion", root );
        //        tr.setToolVersion( version );

        //        String time = getAttributeValue("ScanTime", root);
        //        tr.setTime( time );

        List<Node> findingsList = getNamedChildren("item", root);
        System.out.println("Processing " + findingsList.size() + " findings from ShiftLeft NGSAST");
        for (Node finding : findingsList) {
            try {
                TestCaseResult tcr = parseNGSASTVulnerability(finding);
                if (tcr != null) {
                    tr.put(tcr);
                }
            } catch (Exception e) {
                System.out.println(">> Error detected. Attempting to continue parsing");
                e.printStackTrace();
                return null;
            }
        }
        return tr;
    }

    private TestCaseResult parseNGSASTVulnerability(Node finding) {
        // System.out.println("ShiftLeft NGSAST finding name is: " + finding.getNodeName());

        /* <title type="str">SQL Injection: HTTP data to SQL database via `request` in `BenchmarkTest00774.doPost`</title>
          ...
          <tags type="list">
                <item type="dict">
                        <key type="str">category</key>
                        <value type="str">SQL Injection</value>
                        <shiftleft_managed type="bool">True</shiftleft_managed>
                </item>
                ...
                <item type="dict">
                        <key type="str">cwe_category</key>
                        <value type="str">89</value>
                        <shiftleft_managed type="bool">True</shiftleft_managed>
                </item>
        */
        Node titleNode = getNamedChild("title", finding);
        String title = titleNode.getTextContent();
        // System.out.println("NGSAST finding title is: " + title);

        int testCaseNameLoc = title.indexOf(BenchmarkScore.TESTCASENAME);

        if (testCaseNameLoc > 0) {
            // Get the test case number
            TestCaseResult tcr = new TestCaseResult();

            int testCaseNumLoc = testCaseNameLoc + BenchmarkScore.TESTCASENAME.length();
            String testno = title.substring(testCaseNumLoc, testCaseNumLoc + 5);
            try {
                // System.out.println("Test case number is: " + Integer.parseInt( testno ));
                tcr.setNumber(Integer.parseInt(testno));
            } catch (NumberFormatException e) {
                e.printStackTrace();
            }

            // First get all the tags, then find the CWE entry in those tags

            Node tagsNode = getNamedChild("tags", finding);
            List<Node> tagsList = getNamedChildren("item", tagsNode);
            for (Node tag : tagsList) {

                Node keyNode = getNamedChild("key", tag);

                if ("cwe_category".equals(keyNode.getTextContent())) {
                    Node cweNode = getNamedChild("value", tag);
                    String cweNum = cweNode.getTextContent();
                    // System.out.println("cwe number is: " + cweNum);
                    tcr.setCWE(translate(Integer.parseInt(cweNum)));
                    return tcr;
                }
            }
        } else {
            System.out.println("Skipping NGSAST finding not in Benchmark: " + title);
        }
        return null;
    }

    // This maps the CWE numbers they report to what Benchmark expects when they aren't the same.
    private int translate(int cwe) {
        switch (cwe) {
            case 917:
                return 78; // Command Injection
            case 1004:
                return 614; // Cookie w/out Secure Flag
            case 91:
                return 643; // XPath
            case 916:
                return 328; // Weak Hashing
        }
        return cwe;
    }
}
