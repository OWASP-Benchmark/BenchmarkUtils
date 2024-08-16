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
        String description = getNamedChild("description", flaw).getTextContent();
        tcr.setEvidence(type + "::" + description);

        String name = getAttributeValue("name", flaw);
        int cwe = cweLookup(name);
        tcr.setCWE(cwe);

        String uri = getAttributeValue("url", flaw);
        String testfile = uri.substring(uri.lastIndexOf('/') + 1);
        if (testfile.contains("?")) {
            testfile = testfile.substring(0, testfile.indexOf("?"));
        }

        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setTestID(getBenchmarkStyleTestCaseNumber(testfile));
            return tcr;
        }
        return null;
    }

    private int cweLookup(String name) {
        if (name == null || name.isEmpty()) {
            return CweNumber.UNKNOWN;
        }
        switch (name) {
            case "Cross site scripting vulnerability":
                return CweNumber.XSS;
                // Apparently the rest of the W3AF findings we don't care about so aren't mapped
        }
        return CweNumber.UNKNOWN;
    }
}
