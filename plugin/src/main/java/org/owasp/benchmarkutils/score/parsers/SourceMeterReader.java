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

import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SourceMeterReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".txt") && resultFile.line(0).startsWith("Possible ");
    }

    // Possible Cross-site Scripting Vulnerability:
    // Source: String getValue()
    // Sink: void println(String arg0)
    // Trace:
    // /home/istvan/owasp/ellenorzes/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00023.java(81):(81,30,81,51)[0]
    // /home/istvan/owasp/ellenorzes/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00023.java(80):(80,33,81,51)[0]
    // /home/istvan/owasp/ellenorzes/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00023.java(80):(80,33,81,61)[0]
    // /home/istvan/owasp/ellenorzes/benchmark/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00023.java(80):(80,4,81,62)[0]

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults(
                        "SourceMeter VulnerabilityHunter", true, TestSuiteResults.ToolType.SAST);

        String vuln = null;
        String file = null;
        boolean nextLine = false;
        for (String line : resultFile.lines()) {
            try {
                if (line.length() == 0) {
                    vuln = null;
                    file = null;
                    nextLine = false;
                }
                if (line.startsWith("Possible ")) {
                    System.out.println("\t" + line);
                    vuln = line.substring("Possible ".length());
                    vuln = vuln.substring(0, vuln.length() - " Vulnerability:".length());
                } else if (line.startsWith("Trace:")) {
                    nextLine = true;
                } else if (nextLine) {
                    int idx = line.indexOf(".java");
                    file = line.substring(0, idx);
                    TestCaseResult tcr = parseSourceMeterItem(vuln, file);
                    tr.put(tcr);
                    // System.out.println(tcr.getNumber() + ", " + tcr.getCWE() + ", " +
                    // tcr.getEvidence());
                    nextLine = false;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return tr;
    }

    private TestCaseResult parseSourceMeterItem(String vuln, String file) throws Exception {
        TestCaseResult tcr = new TestCaseResult();

        tcr.setCategory(vuln);
        tcr.setEvidence(file);
        tcr.setCWE(cweLookup(vuln));
        int testno = testNumber(file);
        if (testno > 0) {
            tcr.setNumber(testno);
            return tcr;
        } else {
            return null;
        }
    }

    private static int cweLookup(String vuln) {
        switch (vuln) {
                //        case "insecure-cookie":
                //            return 614; // insecure cookie use
            case "SQL Injection":
                return 89; // sql injection
            case "Command Injection":
                return 78; // command injection
            case "LDAP Injection":
                return 90; // ldap injection
            case "HTTP Response Splitting":
                return 113; // header injection
                //        case "hql-injection":
                //            return 0000; // hql injection
                //        case "unsafe-readline":
                //            return 0000; // unsafe readline
                //        case "reflection-injection":
                //            return 0000; // reflection injection
            case "Cross-site Scripting":
                return 79; // xss
                //        case "xpath-injection":
                //            return 643; // xpath injection
            case "Path Traversal":
                return 22; // path traversal
                //        case "crypto-bad-mac":
                //            return 328; // weak hash
                //        case "crypto-weak-randomness":
                //            return 330; // weak random
                //        case "crypto-bad-ciphers":
                //            return 327; // weak encryption
                //        case "trust-boundary-violation":
                //            return 501; // trust boundary
                //        case "xxe":
                //            return 611; // xml entity
        }
        return 0;
    }
}
