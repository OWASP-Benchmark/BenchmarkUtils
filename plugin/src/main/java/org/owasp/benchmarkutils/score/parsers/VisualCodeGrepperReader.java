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
 * @author Nacho Guisado Obregon
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.StringReader;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class VisualCodeGrepperReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.line(1).startsWith("<CodeIssueCollection");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr =
                new TestSuiteResults("VisualCodeGrepper", false, TestSuiteResults.ToolType.SAST);

        // If the filename includes an elapsed time in seconds (e.g.,
        // TOOLNAME-seconds.xml), set the compute time on the scorecard.
        tr.setTime(resultFile.file());
        NodeList nl = doc.getDocumentElement().getChildNodes();
        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            if (n.getNodeName().equals("CodeIssue")) {
                TestCaseResult tcr = parseVisualCodeGrepperIssue(n);
                if (tcr != null) {
                    tr.put(tcr);
                }
            }
        }

        return tr;
    }

    /**
     * Read the data from each code issue reported
     *
     * @param n : the code issue reported
     * @return the test case result
     */
    private TestCaseResult parseVisualCodeGrepperIssue(Node n) {
        /*
         * // Here an example of how the CodeIssues looks <CodeIssue>
         *  <CodeIssue>
         *    <Priority>1</Priority>
         *    <Severity>Critical</Severity>
         *    <Title>Potential SQL Injection</Title>
         *    <Description>The application appears to allow SQL injection via a pre-prepared dynamic SQL statement. No validator plug-ins were located in the application's XML files.</Description>
         *    <FileName>C:\workspace\benchmark\src\main\java\org\owasp\benchmark\testcode\BenchmarkTest01304.java</FileName>
         *    <Line>52</Line>
         *    <CodeLine>			java.sql.PreparedStatement statement = connection.prepareStatement( sql,</CodeLine>
         *    <Checked>False</Checked>
         *    <CheckColour>LawnGreen</CheckColour>
         *  </CodeIssue>
         */

        String classname = getNamedChild("FileName", n).getTextContent();
        classname = (classname.substring(classname.lastIndexOf('\\') + 1)).split("\\.")[0];
        if (classname.startsWith(BenchmarkScore.TESTCASENAME)) {
            TestCaseResult tcr = new TestCaseResult();
            tcr.setNumber(testNumber(classname));

            Node catnode = getNamedNode("Title", n.getChildNodes());
            tcr.setCWE(figureCWE(tcr, catnode));
            tcr.setCategory(getNamedNode("Title", n.getChildNodes()).getTextContent());
            tcr.setConfidence(
                    Integer.parseInt(getNamedNode("Priority", n.getChildNodes()).getTextContent()));
            tcr.setEvidence(getNamedNode("CodeLine", n.getChildNodes()).getTextContent());
            return tcr;
        }
        return null;
    }

    private int figureCWE(TestCaseResult tcr, Node catnode) {
        String cat = null;
        if (catnode != null) {
            cat = catnode.getTextContent();
        }
        if (cat.startsWith("Cipher.getInstance(")) {
            // Weak encryption
            return CweNumber.WEAK_CRYPTO_ALGO;
        } else if (cat.startsWith("Class Contains Public Variable: ")) {
            // Potential SQL Injection
            // return 89;
        }

        switch (cat) {
                // Cookies
            case "Poor Input Validation":
                return CweNumber.INSECURE_COOKIE;

                // Injections
            case "Potential SQL Injection":
                return CweNumber.SQL_INJECTION;
                // case "Operation on Primitive Data Type" : return 89;

                // Command injection
            case "java.lang.Runtime.exec Gets Path from Variable":
                return CweNumber.COMMAND_INJECTION;

                // XPath Injection
            case "FileInputStream":
            case "java.io.FileWriter":
            case "java.io.FileReader":
            case "FileStream Opened Without Exception Handling":
                return CweNumber.XPATH_INJECTION;

                // Weak random
            case "java.util.Random":
                return CweNumber.WEAK_RANDOM;

                // Path traversal
            case "java.io.File":
            case "java.io.FileOutputStream":
            case "getResourceAsStream":
                return CweNumber.PATH_TRAVERSAL;

                // XSS
            case "Potential XSS":
                return CweNumber.XSS;

                // Trust Boundary Violation
            case "getParameterValues":
            case "getParameterNames":
            case "getParameter":
                return CweNumber.TRUST_BOUNDARY_VIOLATION;

            default:
                return 00; // System.out.println( "Unknown vuln category for VisualCodeGrepper: " +
                // cat );
        }
    }
}
