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

import java.io.StringReader;
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

public class W3AFReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml") && resultFile.line(1).startsWith("<w3af-run");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("W3AF", false, TestSuiteResults.ToolType.DAST);
        Node root = doc.getDocumentElement();

        tr.setToolVersion(parseVersion(root));

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

    private String parseVersion(Node root) {
        Node versionNode = getNamedChild("w3af-version", root);
        String version = versionNode.getTextContent();
        version = version.substring(version.indexOf("Version: ") + "Version: ".length());
        return version.substring(0, version.indexOf('\n'));
    }

    private TestCaseResult parseW3AFIssue(Node flaw) {
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
            tcr.setNumber(testNumber(testfile));
            return tcr;
        }
        return null;
    }

    private int cweLookup(String name) {
        if (name == null || name.isEmpty()) {
            return 0000;
        }
        switch (name) {
            case "Cross site scripting vulnerability":
                return CweNumber.XSS;
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
