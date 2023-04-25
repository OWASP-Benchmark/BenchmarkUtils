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
 * @created 2020
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

public class WapitiReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml") && resultFile.line(4).contains("Wapiti");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("Wapiti", false, TestSuiteResults.ToolType.DAST);

        // Get the version of Wapiti out of the generatorVersion <info> element.
        Node root = doc.getDocumentElement();
        Node reportInfo = getNamedChild("report_infos", root);
        List<Node> infoList = getNamedChildren("info", reportInfo);

        for (Node info : infoList) {
            String name = getAttributeValue("name", info);
            if ("generatorVersion".equals(name)) {
                String fullString = info.getTextContent(); // e.g., Wapiti 3.0.3
                String version = fullString.substring(fullString.lastIndexOf(' ') + 1);
                tr.setToolVersion(version);
                break; // Exit for loop when version is found
            }
        }

        //        String time = getAttributeValue("ScanTime", root);
        //        tr.setTime( time );

        // Now parse each <vulnerability> in the set of <vulnerabilities>
        Node vulns = getNamedChild("vulnerabilities", root);
        List<Node> vulnList = getNamedChildren("vulnerability", vulns);

        for (Node vuln : vulnList) {
            // Each vulnerability categority is a 'volunerability' node
            // And then there are <entries> within which each '<entry> is an instance of that vuln
            // type

            // First, get the CWE for all these entries
            int cwe = getCWE(vuln);

            // Then process each entry
            Node entriesNode = getNamedChild("entries", vuln);
            List<Node> entries = getNamedChildren("entry", entriesNode);
            for (Node entry : entries) {
                String path = getNamedChild("path", entry).getTextContent();
                // Note that Path is a URL, not a source code file. So there is no filename
                // extension to trim off
                if (path.contains(BenchmarkScore.TESTCASENAME)) {
                    TestCaseResult tcr = new TestCaseResult();
                    tcr.setCWE(cwe);
                    tcr.setCategory(getAttributeValue("name", vuln));
                    tcr.setEvidence(getNamedChild("curl_command", entry).getTextContent());
                    tcr.setNumber(testNumber(path));
                    tr.put(tcr);
                }
            }
        }
        return tr;
    }

    // Parse the CWE # out of the references included with the vuln
    private int getCWE(Node vuln) {
        int cwe = -1;
        Node refs = getNamedChild("references", vuln);
        List<Node> references = getNamedChildren("reference", refs);
        for (Node ref : references) {
            String title = getNamedChild("title", ref).getTextContent();
            if (title.startsWith("CWE-")) {
                String cweNum = title.substring("CWE-".length(), title.indexOf(":"));
                cwe = cweLookup(cweNum);
            }
        }
        return cwe;
    }

    private int cweLookup(String cwe) {
        switch (cwe) {
            case "22":
                return CweNumber.PATH_TRAVERSAL;
            case "78":
                return CweNumber.COMMAND_INJECTION;
            case "79":
                return CweNumber.XSS;
            case "89": // Normal and Blind SQL Injection
                return CweNumber.SQL_INJECTION;
            case "352":
                return CweNumber.CSRF;
            case "611":
                return CweNumber.XXE;
            case "93": // HTTP Response Splitting
            case "530": // Exposure of Backup file
            case "538": // Htaccess bypass
            case "601": // Open Redirect
            case "798": // Hard Coded credentials
            case "918": // SSRF
                return CweNumber.DONTCARE;

                // Note: Wapiti does report Secure Flag not set on cookie findings, but doesn't
                // report the specific page. Only the entire web app.
            default:
                System.out.println("WARNING: Wapiti-Unmapped CWE number: " + cwe);
        }
        return -1;
    }
}
