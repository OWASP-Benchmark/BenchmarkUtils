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
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.StringReader;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ReshiftReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).contains("Reshift Report");
    }

    private static int cweLookup(String checkerKey) {
        checkerKey = checkerKey.replace("-SECOND-ORDER", "");

        switch (checkerKey) {
            case "Path Traversal (Absolute)":
            case "Path Traversal (Read)":
            case "Path Traversal (Relative)":
            case "Path Traversal (Write)":
                return 22; // path traversal

            case "SQL Injection (Hibernate)":
            case "SQL Injection (Java Database Connectivity)":
            case "SQL Injection (JDBC)":
            case "SQL Injection (Non-constant String)":
            case "SQL Injection (Prepared Statement)":
                return 89; // sql injection

            case "Arbitrary Command Execution":
                return 78; // command injection
            case "XPath Injection":
                return 643; // xpath injection
            case "Cipher is Susceptible to Padding Oracle":
            case "Cipher With No Integrity":
            case "DES is Insecure":
            case "DESede is Insecure":
            case "Static IV":
                return 327; // weak encryption
            case "MD2, MD4 and MD5 Are Weak Hash Functions":
            case "SHA-1 is a Weak Hash Function":
                return 328; // weak hash
            case "LDAP Injection":
                return 90; // ldap injection
            case "Cross-Site Scripting (XSS-Servlet Output)":
                return 79; // xss

            default:
                System.out.println(
                        "WARNING: Unmapped Vulnerability category detected: " + checkerKey);
        }
        return 0;
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Reshift", true, TestSuiteResults.ToolType.SAST);

        /* The start of a Reshift .csv results file looks like this (where I've added the line #'s in front):

        1: Reshift Report
        2: BenchmarkJava
        3: 2021-12-10
        4: https://github.com/OWASP-Benchmark/BenchmarkJava
        5: ""
        6: ""
        7: ,Branch,Category,Severity,OWASP-Top-10,PCI,Commit,Scan-Date,Status,Suppression-User,Suppression-Comments,Issue-File
        8: ,origin/master,Path Traversal (Read),HIGH,,,72258cb82f39e4e4b455e97f2aed2e5d37916bff,2021-12-10 22:19:24.233641+00:00,Open,,,https://github.com/OWASP-Benchmark/BenchmarkJava/blob/72258cb82f39e4e4b455e97f2aed2e5d37916bff/src%2Fmain%2Fjava%2Forg%2Fowasp%2Fbenchmark%2Ftestcode%2FBenchmarkTest02294.java
        N: The rest of the results lines from here to end ...

        */
        java.io.BufferedReader inReader =
                new java.io.BufferedReader(new StringReader(resultFile.content()));
        for (int i = 1; i <= 6; i++) { // Read 6 lines so we can skip over the preamble
            inReader.readLine();
        }

        String header =
                "None" + inReader.readLine(); // Have append this to the front as the 1st column is
        // not named.
        CSVFormat.Builder CSVBuilder = CSVFormat.Builder.create(CSVFormat.RFC4180);
        CSVBuilder.setHeader(header.split(","));
        Iterable<CSVRecord> records = CSVBuilder.get().parse(inReader);

        for (CSVRecord record : records) {
            String url = record.get("Issue-File");

            try {
                if (url.contains(BenchmarkScore.TESTCASENAME)) {
                    TestCaseResult tcr = new TestCaseResult();
                    String category = record.get("Category");
                    tcr.setCategory(category);
                    tcr.setCWE(cweLookup(category));
                    tcr.setNumber(testNumber(url));
                    if (tcr.getCWE() != 0) {
                        tr.put(tcr);
                    }
                }
            } catch (NumberFormatException e) {
                System.out.println("> Parse error: " + record.toString());
            }
        }

        tr.setTime("100");

        return tr;
    }
}
