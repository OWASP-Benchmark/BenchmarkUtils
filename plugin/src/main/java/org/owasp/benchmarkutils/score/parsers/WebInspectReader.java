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

import java.util.List;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

public class WebInspectReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("Scan");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("HP WebInspect", true, TestSuiteResults.ToolType.DAST);

        // <Scan><Name>Site:
        // https://10.240.28.203:8443/benchmark/</Name><PolicyName>Standard</PolicyName>
        // <StartTime>9/11/2015 1:56:13
        // PM</StartTime><Duration>02:59:39.0365257</Duration><Issues><Issue>

        String duration = getNamedChild("Duration", resultFile.xmlRootNode()).getTextContent();
        duration = duration.substring(0, duration.indexOf('.'));
        tr.setTime(duration);

        Node issues = getNamedChild("Issues", resultFile.xmlRootNode());
        List<Node> issueList = getNamedChildren("Issue", issues);

        for (Node issue : issueList) {
            try {
                TestCaseResult tcr = parseWebInspectIssue(issue);
                if (tcr != null) {
                    tr.put(tcr);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return tr;
    }

    //    <Issue>
    //    <CheckTypeID>Vulnerability</CheckTypeID>
    //    <EngineType>REQMOD</EngineType>
    //    <URL>https://10.240.28.203:8443/benchmark/BenchmarkTest02607.html</URL>
    //    <Scheme>https</Scheme>
    //    <Host>10.240.28.203</Host>
    //    <Port>8443</Port>
    //    <TriggerSession null="1"/>
    //    <VulnerabilityID>11306</VulnerabilityID>
    //    <Severity>1</Severity>
    //    <Name>Server Misconfiguration: Cache Policy</Name>

    private TestCaseResult parseWebInspectIssue(Node flaw) throws Exception {
        TestCaseResult tcr = new TestCaseResult();

        String cat = getNamedChild("Name", flaw).getTextContent();
        tcr.setEvidence(cat);

        Node vulnId = getNamedChild("VulnerabilityID", flaw);
        if (vulnId != null) {
            String vuln = vulnId.getTextContent();
            int cwe = cweLookup(vuln);
            tcr.setCWE(cwe);
        }

        String conf = getNamedChild("Severity", flaw).getTextContent();
        tcr.setConfidence(Integer.parseInt(conf));

        String uri = getNamedChild("URL", flaw).getTextContent();
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

    private int cweLookup(String rule) {
        switch (rule) {
            case "810":
            case "1436":
            case "1498":
                return CweNumber.DONTCARE; // Poor Error Handling: Unhandled Exception

            case "4720":
                return CweNumber.INSECURE_COOKIE; // Cookie Security: Cookie Not Sent Over SSL
            case "4724":
                return CweNumber.DONTCARE; // Password Management: Unmasked Password Field
            case "4725":
                return CweNumber
                        .DONTCARE; // Server Misconfiguration: SSL Certificate Hostname Discrepancy
            case "4729":
                return CweNumber.DONTCARE; // Transport Layer Protection: Insecure Transmission
            case "5546":
                return CweNumber.DONTCARE; // Compliance Failure: Missing Privacy Policy
            case "5597":
                return CweNumber.DONTCARE; // Privacy Violation: Autocomplete
            case "5649":
                return CweNumber.XSS; // Cross-Site Scripting: Reflected
            case "10167":
                return CweNumber.DONTCARE; // Password Management: Insecure Submission
            case "10210":
                return CweNumber.DONTCARE; // Access Control: Unprotected Directory
            case "10237":
                return CweNumber.DONTCARE; // Privacy Violation: Credit Card Number
            case "10543":
                return CweNumber.COOKIE_WITHOUT_HTTPONLY; // Cookie Security: HTTPOnly not Set
            case "10655":
                return CweNumber
                        .DONTCARE; // Application Misconfiguration: Exposure of POST Parameters in
                // GET
                // Request
            case "10825":
                return CweNumber.DONTCARE; // Privacy Violation: Credit Card Number
            case "10932":
                return CweNumber.DONTCARE; // Poor Error Handling: Server Error Message
            case "10965":
                return CweNumber.DONTCARE; // Transport Layer Protection: Insecure Transmission
            case "11293":
            case "11294":
                return CweNumber.XSS; // Cross-Frame Scripting
            case "11299":
                return CweNumber.SQL_INJECTION; // SQL Injection: Blind
            case "11306":
                return CweNumber.DONTCARE; // Server Misconfiguration: Cache Policy
            case "11359":
                return CweNumber.DONTCARE; // Server Misconfiguration: Response Headers
            case "11365":
                return CweNumber.DONTCARE; // Insecure SSL: Missing Http Strict Transport
            case "11380":
                return CweNumber.DONTCARE; // Often Misused: Weak SSL Certificate
            case "11395":
                return CweNumber.DONTCARE; // Transport Layer Protection: Weak SSL Protocol

            default:
                System.out.println("WARNING: Unknown WebInspect vuln category: " + rule);
        }

        return CweNumber.UNKNOWN;
    }
}
