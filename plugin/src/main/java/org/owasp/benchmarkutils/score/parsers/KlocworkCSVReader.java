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
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.StringReader;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class KlocworkCSVReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).contains("State")
                && resultFile.line(0).contains("Taxonomy");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Klocwork", true, TestSuiteResults.ToolType.SAST);

        /* The start of a Klocwork .csv results file looks like this (where I've added the line #'s in front):

        File,Path,Line,Method,Code,Severity,State,Status,Taxonomy,Owner
        DataBaseServer.java,/opt/klocwork/projects_root/projects/BenchmarkJavaToo/src/main/java/org/owasp/benchmark/helpers/DataBaseServer.java,65,getAll(),RLK.SQLOBJ,Critical (1),New,Analyze,Java,unowned
        DatabaseHelper.java,/opt/klocwork/projects_root/projects/BenchmarkJavaToo/src/main/java/org/owasp/benchmark/helpers/DatabaseHelper.java,174,executeSQLCommand(),EXC.BROADTHROWS,Review (4),New,Analyze,Java,unowned

                */
        java.io.BufferedReader inReader =
                new java.io.BufferedReader(new StringReader(resultFile.content()));

        String header = inReader.readLine();
        CSVFormat.Builder CSVBuilder = CSVFormat.Builder.create(CSVFormat.RFC4180);
        CSVBuilder.setHeader(header.split(","));
        Iterable<CSVRecord> records = CSVBuilder.get().parse(inReader);

        for (CSVRecord record : records) {
            String category = record.get("Code"); // e.g., RLK.SQLOBJ
            String filename = record.get("File"); // e.g., BenchmarkTest00001

            TestCaseResult tcr = new TestCaseResult();
            tcr.setCategory(category);
            tcr.setCWE(cweLookup(category));
            if (filename.startsWith(BenchmarkScore.TESTCASENAME)) {
                tcr.setNumber(testNumber(filename));
            }

            if (tcr.getCWE() != 0) {
                tr.put(tcr);
            }
        }

        tr.setTime("100"); // Why 100?

        return tr;
    }

    private int cweLookup(String checkerKey) {

        // We don't care about non-vulnerability findings
        if (!checkerKey.startsWith("SV.")) return CweNumber.DONTCARE;

        switch (checkerKey) {
                // These few are OBE because of the SV. check above, but left in, in case we want to
                // check them all in the future. THis is only a very partial list.
            case "ECC.EMPTY": // Empty Catch Clause
            case "ESCMP.EMPTYSTR": // Inefficient empty string comparison
            case "JD.UNCAUGHT": // Uncaught exception
            case "JD.VNU.NULL": // Variable was never read after being assigned
            case "RLK.IN": // Input stream not closed on exit
            case "RLK.OUT": // Output stream not closed on exit

            case "SV.DATA.DB": // Data Injection - what does that mean? TODO
            case "SV.PASSWD.HC": // Hardcoded Password
            case "SV.PASSWD.HC.EMPTY": // Empty Password
            case "SV.PASSWD.PLAIN": // Plain-text Password
            case "SV.SENSITIVE.DATA": // Unencrypted sensitive data is written
                return CweNumber.DONTCARE;

            case "SV.DATA.BOUND": // Untrusted Data leaks into trusted storage
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case "SV.EXEC": // Process Injection
            case "SV.EXEC.ENV": // Process Injection Environment Variables
            case "SV.EXEC.LOCAL": // Process Injection. Local Arguments
            case "SV.EXEC.PATH": // Untrusted Search Path
                return CweNumber.COMMAND_INJECTION;
            case "SV.HASH.NO_SALT": // Use of a one-way cryptographic hash without a salt
                return 759; // CWE-759: Use of a One-Way Hash without a Salt
                // Not the same as: CweNumber.WEAK_HASH_ALGO; - CWE: 328 Weak Hashing
            case "SV.LDAP": // Unvalidated user input is used as LDAP filter
                return CweNumber.LDAP_INJECTION;
            case "SV.PATH": // Path and file name injection
            case "SV.PATH.INJ": // File injection
                return CweNumber.PATH_TRAVERSAL;
            case "SV.RANDOM": // Use of insecure Random number generator
                return CweNumber.WEAK_RANDOM;
            case "SV.SQL": // SQL Injection
                return CweNumber.SQL_INJECTION;
            case "SV.WEAK.CRYPT": // Use of a Broken or Risky Cryptographic Algorithm
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "SV.XPATH": // Unvalidated user input is used as an XPath expression
                return CweNumber.XPATH_INJECTION;
            case "SV.XSS.COOKIE": // Sensitive cookie without setHttpOnly flag
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;
            case "SV.XSS.DB": // Cross Site Scripting (Stored XSS)
            case "SV.XSS.REF": // Cross Site Scripting (Reflected XSS)
                return CweNumber.XSS;
            case "SV.XXE.DBF": // Possibility for XML External Entity attack
            case "SV.XXE.SF":
            case "SV.XXE.SPF":
            case "SV.XXE.TF":
            case "SV.XXE.XIF":
            case "SV.XXE.XRF":
                return CweNumber.XXE;

            default:
                System.out.println(
                        "WARNING: Unmapped Vulnerability category detected: " + checkerKey);
                return 0;
        }
    }
}
