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

import java.io.File;
import java.io.FileInputStream;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

public class W3AFReader extends Reader {

    public TestSuiteResults parse(File f) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(f));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("W3AF", true, TestSuiteResults.ToolType.DAST);
        Node root = doc.getDocumentElement();

        //        <w3af-run start="1497433673" start-long="Wed Jun 14 11:47:53 2017" version="2.1">
        //           <w3af-version>w3af - Web Application Attack and Audit Framework
        //              Version: 1.7.6
        //              Revision: 27b1516a3f - 04 Apr 2017 20:45
        //           </w3af-version>

        //      Only start time available in XML. No stop time
        //        String duration = getNamedChild("scantime", root ).getTextContent();
        //        try {
        //            long millis = Long.parseLong(duration);
        //            tr.setTime( TestResults.formatTime( millis ) );
        //        } catch( Exception e ) {
        //            tr.setTime( duration );
        //        }

        Node versionNode = getNamedChild("w3af-version", root);
        String version = versionNode.getTextContent();
        version = version.substring(version.indexOf("Version: ") + "Version: ".length());
        version = version.substring(0, version.indexOf('\n'));
        tr.setToolVersion(version);

        List<Node> issueList = getNamedChildren("vulnerability", root);

        for (Node issue : issueList) {
            try {
                TestCaseResult tcr = parseW3AFIssue(issue);
                if (tcr != null) {
                    tr.put(tcr);
                    // System.out.println( tcr.getNumber() + ", " + tcr.getCategory() + ", " +
                    // tcr.getCWE() + ", " + tcr.getEvidence() );
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return tr;
    }

    //        <vulnerability id="[483744]" method="GET" name="Cross site scripting vulnerability"
    // plugin="xss" severity="Medium"
    // url="https://localhost:8443/benchmark/xss-03/BenchmarkTest01657" var="BenchmarkTest01657">
    //            <fix-effort>10</fix-effort>
    //            <references>
    //                <reference title="WASC"
    // url="http://projects.webappsec.org/w/page/13246920/Cross%20Site%20Scripting"/>
    //                <reference title="Secunia" url="http://secunia.com/advisories/9716/"/>
    //                <reference title="OWASP"
    // url="https://owasp.org/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet"/>
    //            </references>
    //        </vulnerability>

    private TestCaseResult parseW3AFIssue(Node flaw) throws Exception {
        TestCaseResult tcr = new TestCaseResult();

        String type = getAttributeValue("plugin", flaw);
        tcr.setCategory(type);

        String confidence = getNamedChild("fix-effort", flaw).getTextContent();
        tcr.setConfidence(Integer.parseInt(confidence));

        String severity = getAttributeValue("severity", flaw);
        String description = getNamedChild("description", flaw).getTextContent();
        tcr.setEvidence(severity + "::" + description);

        String name = getAttributeValue("name", flaw);
        int cwe = cweLookup(name);
        tcr.setCWE(cwe);

        String uri = getAttributeValue("url", flaw);
        String testfile = uri.substring(uri.lastIndexOf('/') + 1);
        if (testfile.contains("?")) {
            testfile = testfile.substring(0, testfile.indexOf("?"));
        }

        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            String testno = testfile.substring(BenchmarkScore.TESTCASENAME.length());
            if (testno.endsWith(".html")) {
                testno = testno.substring(0, testno.length() - 5);
            }
            try {
                tcr.setNumber(Integer.parseInt(testno));
                return tcr;
            } catch (NumberFormatException e) {
                System.out.println("> Parse error " + testfile + ":: " + testno);
            }
        }
        return null;
    }

    private static int cweLookup(String name) {
        if (name == null || name.isEmpty()) {
            return 0000;
        }
        switch (name) {
            case "Cross site scripting vulnerability":
                return 79; // xss
                //        case "insecure-cookie"           :  return 614;  // insecure cookie use
                //        case "sql-injection"             :  return 89;   // sql injection
                //        case "cmd-injection"             :  return 78;   // command injection
                //        case "ldap-injection"            :  return 90;   // ldap injection
                //        case "header-injection"          :  return 113;  // header injection
                //        case "hql-injection"             :  return 0000; // hql injection
                //        case "unsafe-readline"           :  return 0000; // unsafe readline
                //        case "reflection-injection"      :  return 0000; // reflection injection
                //        case "reflected-xss"             :  return 79;   // xss
                //        case "xpath-injection"           :  return 643;  // xpath injection
                //        case "path-traversal"            :  return 22;   // path traversal
                //        case "crypto-bad-mac"            :  return 328;  // weak hash
                //        case "crypto-weak-randomness"    :  return 330;  // weak random
                //        case "crypto-bad-ciphers"        :  return 327;  // weak encryption
                //        case "trust-boundary-violation"  :  return 501;  // trust boundary
                //        case "xxe"                       :  return 611;  // xml entity
        }
        return 0000;
    }
}
