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

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SeekerReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).contains("CheckerKey")
                && resultFile.line(0).contains("LastDetectionURL");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Seeker", true, TestSuiteResults.ToolType.IAST);

        java.io.Reader inReader = new java.io.StringReader(resultFile.content());
        Iterable<CSVRecord> records = CSVFormat.RFC4180.withFirstRecordAsHeader().parse(inReader);
        for (CSVRecord record : records) {
            String checkerKey = record.get("CheckerKey");
            String url = record.get("LastDetectionURL");

            TestCaseResult tcr = new TestCaseResult();
            tcr.setCategory(checkerKey);
            tcr.setCWE(cweLookup(checkerKey));
            tcr.setNumber(testNumber(url));
            if (tcr.getCWE() != 0) {
                tr.put(tcr);
            }
        }

        tr.setTime("100");

        return tr;
    }

    private int cweLookup(String checkerKey) {
        checkerKey = checkerKey.replace("-SECOND-ORDER", "");

        switch (checkerKey) {
            case "COOK-SEC":
                return 614; // insecure cookie use
            case "SQLI":
                return 89; // sql injection
            case "CMD-INJECT":
                return 78; // command injection
            case "LDAP-INJECTION":
                return 90; // ldap injection
            case "header-injection":
                return 113; // header injection
            case "hql-injection":
                return 564; // hql injection
            case "unsafe-readline":
                return 0000; // unsafe readline
            case "reflection-injection":
                return 0000; // reflection injection
            case "R-XSS":
                return 79; // XSS
            case "XPATH-INJECT":
                return 643; // XPath injection
            case "DIR-TRAVERSAL":
                return 22; // path traversal
            case "crypto-bad-mac":
                return 328; // weak hash
            case "crypto-weak-randomness":
                return 330; // weak random
            case "WEAK-ENC":
                return 327; // weak encryption
            case "trust-boundary-violation":
                return 501; // trust boundary
            case "xxe":
                return 611; // XML Entity Injection
            case "WEAK-HASH":
                return 328;
            case "WEAK-RANDOM-GENERATOR":
                return 330;
            case "TRUST-BOUNDARY-VIOLATION":
                return 501;

            default:
                System.out.println(
                        "WARNING: Unmapped Vulnerability category detected: " + checkerKey);
        }
        return 0;
    }
}
