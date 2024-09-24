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

        if (isTestCaseFile(testfile)) {
            tcr.setActualResultTestID(testfile);
            return tcr;
        }
        return null;
    }

    private int cweLookup(String cweNum) {
        if (cweNum == null || cweNum.isEmpty()) {
            return CweNumber.UNKNOWN;
        }
        int cwe = Integer.parseInt(cweNum);
        switch (cwe) {
            case 80: // TODO/FIXME - Is this correct? Shouldn't this be mapped to XSS?
                return CweNumber.INSECURE_COOKIE; // insecure cookie use
        }
        return cwe;
    }
}
