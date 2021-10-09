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
 * @created 2016
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.FileInputStream;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class CASTAIPReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.line(1).toLowerCase().startsWith("<castaip");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(resultFile.file()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr =
                new TestSuiteResults("CAST AIP", true, TestSuiteResults.ToolType.SAST);
        Node root = doc.getDocumentElement();

        //      <?xml version="1.0" encoding="UTF-8"?>
        //      <CASTAIP version="8.2.3" timestamp="2017-09-18 11:55:12.312+00">

        //      Only start time available in XML, per above. No stop time
        //        String duration = getNamedChild("timestamp", root ).getTextContent();
        //        try {
        //            long millis = Long.parseLong(duration);
        //            tr.setTime( TestResults.formatTime( millis ) );
        //        } catch( Exception e ) {
        //            tr.setTime( duration );
        //        }

        String version = getAttributeValue("version", root);
        if (version != null) {
            tr.setToolVersion(version);
        }

        List<Node> issueList = getNamedChildren("file", root);

        for (Node issue : issueList) {
            try {
                TestCaseResult tcr = parseCASTAIPIssue(issue);
                if (tcr != null) {
                    tr.put(tcr);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return tr;
    }

    // Issues look like this (all on one line)
    // <file name="C:\CASTMS\Deploy\OWASPTST\My
    // Package\src\main\java\org\owasp\benchmark\testcode\BenchmarkTest00007.java">
    // <violation beginline="39" endline="70" begincolumn="2" endcolumn="3" rule=" " ruleset="Secure
    // Coding - Input Validation"
    // fullname="org.owasp.benchmark.testcode.BenchmarkTest00007.doPost" type="Java Method"
    // critical="YES" >
    // Avoid OS command injection vulnerabilities ( CWE-78 )</violation></file>

    private TestCaseResult parseCASTAIPIssue(Node flaw) throws Exception {
        TestCaseResult tcr = new TestCaseResult();

        // Get the violation description and if it doesn't contain a CWE #, then it's not
        // relevant to Benchmark.
        String violation = getNamedChild("violation", flaw).getTextContent();
        if (!violation.contains("CWE-")) return null;

        // Get CWE #
        violation = violation.substring(violation.indexOf("CWE-") + "CWE-".length());
        violation = violation.substring(0, violation.indexOf(')'));
        int cwe = cweLookup(violation);
        tcr.setCWE(cwe);

        // Get Benchmark test case #. If it's not in a Benchmark test case, return null
        String filename = getAttributeValue("name", flaw);
        filename = filename.replaceAll("\\\\", "/");
        filename = filename.substring(filename.lastIndexOf('/') + 1);
        if (filename.startsWith(BenchmarkScore.TESTCASENAME)) {
            String testNumber =
                    filename.substring(
                            BenchmarkScore.TESTCASENAME.length(), filename.lastIndexOf('.'));
            try {
                tcr.setNumber(Integer.parseInt(testNumber));
                return tcr;
            } catch (NumberFormatException e) {
                System.out.println("> Parse error " + filename + ":: " + testNumber);
            }
        }
        return null;
    }

    private int cweLookup(String name) {
        if (name == null || name.isEmpty()) {
            return 0000;
        }
        switch (name.trim()) {
            case "614":
                return CweNumber.INSECURE_COOKIE;
            case "78":
                return CweNumber.COMMAND_INJECTION;
            case "79":
                return CweNumber.XSS;
            case "89":
                return CweNumber.SQL_INJECTION;
            case "90":
                return CweNumber.LDAP_INJECTION;
                //        case "header-injection"          :  return 113;  // header injection
                //        case "hql-injection"             :  return 0000; // hql injection
                //        case "unsafe-readline"           :  return 0000; // unsafe readline
                //        case "reflection-injection"      :  return 0000; // reflection injection
                //        case "reflected-xss"             :  return 79;   // xss
            case "91":
            case "643":
                return CweNumber.XPATH_INJECTION;
            case "73": // This tool calls this CWE-73 "External Control of File"
            case "22":
                return CweNumber.PATH_TRAVERSAL;
                // Name or Path"
                //        case "crypto-bad-mac"            :  return 328;  // weak hash
                //        case "crypto-weak-randomness"    :  return 330;  // weak random
                //        case "crypto-bad-ciphers"        :  return 327;  // weak encryption
            case "501":
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
                //        case "xxe"                       :  return 611;  // xml entity
            case "134":
                return CweNumber
                        .EXTERNALLY_CONTROLLED_STRING; // Use of Externally-Controlled Format String
                // - Which really isn't a
            default:
                System.out.println(
                        "No matching CWE # found in CAST AIP Reader for: 'CWE-" + name + "'");
        }
        return 0000;
    }
}
