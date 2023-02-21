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

import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

public class NetsparkerReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("netsparker");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Netsparker", true, TestSuiteResults.ToolType.DAST);

        Node target = getNamedChild("target", resultFile.xmlRootNode());

        String duration = getNamedChild("scantime", target).getTextContent();
        try {
            long millis = Long.parseLong(duration);
            tr.setTime(TestSuiteResults.formatTime(millis));
        } catch (Exception e) {
            tr.setTime(duration);
        }

        List<Node> issueList = getNamedChildren("vulnerability", resultFile.xmlRootNode());

        for (Node issue : issueList) {
            try {
                TestCaseResult tcr = parseNetsparkerIssue(issue);
                if (tcr != null) {
                    tr.put(tcr);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return tr;
    }

    private TestCaseResult parseNetsparkerIssue(Node flaw) {
        TestCaseResult tcr = new TestCaseResult();

        String type = getNamedChild("type", flaw).getTextContent();
        tcr.setCategory(type);

        String severity = getNamedChild("severity", flaw).getTextContent();

        String confidence = getNamedChild("certainty", flaw).getTextContent();
        tcr.setConfidence(Integer.parseInt(confidence));

        Node extra = getNamedChild("extrainformation", flaw);
        Node info = getNamedChild("info", extra);
        String evidence = getAttributeValue("name", info);
        tcr.setEvidence(severity + "::" + evidence);

        Node classification = getNamedChild("classification", flaw);

        // Note: not all vulnerabilities have CWEs in Netsparker
        if (classification != null) {
            Node vulnId = getNamedChild("CWE", classification);
            if (vulnId != null) {
                String cweNum = vulnId.getTextContent();
                int cwe = cweLookup(cweNum);
                tcr.setCWE(cwe);
            }
        }

        String uri = getNamedChild("url", flaw).getTextContent();
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

    private int cweLookup(String cweNum) {
        if (cweNum == null || cweNum.isEmpty()) {
            return 0000;
        }
        int cwe = Integer.parseInt(cweNum);
        switch (cwe) {
            case 80:
                return CweNumber.INSECURE_COOKIE; // insecure cookie use
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
        return cwe;
    }
}
