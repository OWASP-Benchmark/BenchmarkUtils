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
 * @author Fausto Spoto <a href="http://www.juliasoft.com">Julia Srl</a>
 * @created 2016
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class JuliaReader extends Reader {

    // refactoring resilient
    // TODO: Update to handle package paths from other test suites
    private final String prefixOfTest =
            "org.owasp.benchmark.testcode." + BenchmarkScore.TESTCASENAME;

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && (resultFile.line(1).startsWith("<analysisResult")
                        || resultFile.line(1).startsWith("<analysisReportResult"));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        docBuilderFactory.setFeature(
                "http://apache.org/xml/features/disallow-doctype-decl", true); // Prevent XXE
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("Julia", true, TestSuiteResults.ToolType.SAST);

        Node root = doc.getDocumentElement();

        // Get run time from results file
        String runDuration = getNamedChild("runDuration", root).getTextContent();
        tr.setTime(TestSuiteResults.formatTime(runDuration));

        // Get the version number from the results file
        String juliaVersion = getNamedChild("engineVersion", root).getTextContent();
        tr.setToolVersion(juliaVersion);

        // Now pull all the test results out and return them.
        NodeList nl = root.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            if (n.getNodeName().equals("warning")) {
                TestCaseResult tcr = parseJuliaBug(n);
                if (tcr.getNumber() > 0) tr.put(tcr);
            }
        }

        return tr;
    }

    private TestCaseResult parseJuliaBug(Node n) {
        TestCaseResult tcr = new TestCaseResult();

        NodeList nl = n.getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node child = nl.item(i);
            String childName = child.getNodeName();
            if (childName.equals("source")) {
                String where = child.getTextContent().replace('/', '.');
                // "org.owasp.benchmark.testcode.BenchmarkTest00042.java"
                tcr.setNumber(testNumber(where));

            } else if (childName.equals("CWEid"))
                tcr.setCWE(Integer.parseInt(child.getTextContent()));
        }

        return tcr;
    }
}
