/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https:/owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.TestSuiteResults.ToolType;

/*
 * This Reader was contributed by ShiftLeft and is used to parse a custom .csv file their custom scripts
 * produce. Each line of this file, which has to have the extension .sl, looks like this:
 *    #####,VulnType - where ##### is the Benchmark test case numbner, and
 *                     VulnType is a string that can be mapped to a CWE #.
 */

public class ShiftLeftReader2 extends Reader {
    public TestSuiteResults parse(File f) throws IOException {

        TestSuiteResults tr = new TestSuiteResults("ShiftLeft", true, ToolType.SAST);
        BufferedReader reader = new BufferedReader(new FileReader(f));

        String line;
        while ((line = reader.readLine()) != null) {

            String[] split = line.split(":");
            if (split.length != 2) {
                System.out.println("Invalid line in SL_Titles result file: " + line);
            }

            int cwe = categoryToCWE(split[0], split[1]);

            if (cwe != -1) {
                // Parse out the test case number and set it in the
                if (split[1].indexOf(BenchmarkScore.TESTCASENAME) < 0) {
                    continue; // Some findings are not in test cases - so skip those
                    // e.g., Weak Hash: Usage of weak hashing function in `Properties.getProperty`
                }

                TestCaseResult testCaseResult = new TestCaseResult();
                // testCaseResult.setCategory(category);  // Needed??

                String testno =
                        split[1].substring(
                                split[1].indexOf(BenchmarkScore.TESTCASENAME)
                                        + BenchmarkScore.TESTCASENAME.length());
                testno = testno.substring(0, 5);
                try {
                    testCaseResult.setNumber(Integer.parseInt(testno));
                } catch (NumberFormatException e) {
                    System.out.println("> Test case # parse error: " + testno);
                    continue; // Move on to next finding
                }

                testCaseResult.setCWE(cwe);
                testCaseResult.setEvidence(line);

                tr.put(testCaseResult);
            }
        }

        reader.close();
        return tr;
    }

    private int categoryToCWE(String category, String restOfLine) {
        switch (category) {
            case "Remote Code Execution":
                return 78;
                //      case "crypto":  // Apparently they have no default crypto rules.
                //        return 327;
            case "Weak Hash":
                return 328;
            case "LDAP Injection":
                return 90;
            case "Directory Traversal":
                return 22;
            case "securecookie": // See below
                return 614;
            case "SQL Injection":
                return 89;
            case "Session Injection":
                return 501;
            case "Weak Random":
                return 330;
            case "XPath Injection":
                return 643;
            case "XSS":
                return 79;
            case "Cookie Injection":
                return -1; // Don't care
            case "File Write":
                return -1; // Don't care
            case "Open redirect":
                return -1; // Don't care
            case "Sensitive Data Leak":
                // Handle this:
                // Sensitive Data Leak: Cookies are used without `secure` attribute set via in
                // `BenchmarkTest01682.doPost`
                if (restOfLine.contains("without `secure`")) return 614;
                else return -1;
            default:
                System.out.println("Ignoring unknown ShiftLeft vuln category: " + category);
                return -1;
        }
    }
}
