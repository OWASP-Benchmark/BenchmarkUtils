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
 * @created 2025
 */
package org.owasp.benchmarkutils.score.parsers;

import java.util.List;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

/**
 * The Roslynator XML reader parses the XML results file generated when you use the Roslynator
 * analyzer to analyze then export results to an XML file.
 */
public class RoslynatorXMLReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        /*
         * XML file starts with:
         *    <?xml version="1.0" encoding="UTF-8"?>
         *    <Roslynator>
         *      <CodeAnalysis>
         *        <Summary> ...
         */
        return resultFile.filename().endsWith(".xml")
                && (resultFile.line(1).contains("Roslynator"));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Roslynator", true, TestSuiteResults.ToolType.SAST);

        //        Node roslynatorNode = getNamedChild("Roslynator", resultFile.xmlRootNode());
        Node codeAnalysisNode = getNamedChild("CodeAnalysis", resultFile.xmlRootNode());
        if (codeAnalysisNode == null) {
            System.out.println(
                    "No CodeAnalysis Node found in Roslynator results file: '"
                            + resultFile.filename()
                            + "' so no findings.");
            return tr;
        }
        Node projectsNode = getNamedChild("Projects", codeAnalysisNode);
        if (projectsNode == null) {
            System.out.println(
                    "No Projects Node found under CodeAnalysis in Roslynator results file: '"
                            + resultFile.filename()
                            + "' so no findings.");
            return tr;
        }
        Node projectNode = getNamedChild("Project", projectsNode);
        if (projectsNode == null) {
            System.out.println(
                    "No Project Node found under Project in Roslynator results file: '"
                            + resultFile.filename()
                            + "' so no findings.");
            return tr;
        }
        Node diagnosticsNode = getNamedChild("Diagnostics", projectNode);
        if (diagnosticsNode == null) {
            System.out.println(
                    "No Diagnostics Node found under Project in Roslynator results file: '"
                            + resultFile.filename()
                            + "' so no findings.");
            return tr;
        }
        List<Node> diagnostics = getNamedChildren("Diagnostic", diagnosticsNode);

        for (Node diagnostic : diagnostics) {
            String ruleId = getAttributeValue("Id", diagnostic);
            String filename = getNamedChild("FilePath", diagnostic).getTextContent();
            String message = getNamedChild("Message", diagnostic).getTextContent();

            // There are some rules where the file location is not specified directly in the
            // filename attribute
            if (filename == null) {
                // TBD - FIXME
                System.err.println("ERROR: Found Diagnostic node with no FilePath child Node.");
            }

            if (isTestCaseFile(filename)) {
                int CWE = cweLookup(ruleId, message, filename);
                if (CWE != CweNumber.DONTCARE) {
                    TestCaseResult tcr = new TestCaseResult();
                    tcr.setActualResultTestID(TestSuiteResults.getFileNameNoPath(filename));
                    tcr.setCWE(CWE);
                    tr.put(tcr);
                }
            } else {
                // Do nothing. Skip results for non-test files.
            }
        }
        return tr;
    }

    /**
     * This method maps Roslynator rule Ids to their corresponding CWE number, or -1, if we don't
     * care about it.
     */
    private int cweLookup(String ruleid, String ruleMsg, String filename) {
        switch (ruleid) {
            case "CS0105": // Using directive appeared previously in this namespace
            case "CS0649": // Field is never assigned to, and will always have its default value
                return CweNumber.DONTCARE;
            case "CS0162": // Unreachable code detected
            case "CS0168": // Variable is declared but never used
                return 561; // CWE-561 Dead Code
            case "CS0169": // Field is never used
            case "CS0219": // Variable is assigned but its value is never used
            case "CS0414": // Field is assigned but its value is never used
                return 563; // CWE-563: Assignment to Variable without Use
            case "CS0618": // Type or member is obsolete
                return 477; // CWE-477: (Obsolete Function)
            case "CS0642": // Possible mistaken empty statement
                return 483; // CWE-483 Incorrect Block Delimitation

            case "CS0665": // Assignment in conditional expression is always constant
            case "CS1717": // Assignment made to same variable
                return 481; // CWE-481: Assigning instead of Comparing

            default:
                System.err.println(
                        "WARNING: no CWE mapping provided for ruleid id: '"
                                + ruleid
                                + "' with message: '"
                                + ruleMsg
                                + "' for file: "
                                + TestSuiteResults.getFileNameNoPath(filename));
        }
        return CweNumber.UNMAPPED;
    }
}
