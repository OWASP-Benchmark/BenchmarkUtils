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
 * @created 2024
 */
package org.owasp.benchmarkutils.score.parsers;

import java.util.List;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

/**
 * The Klocwork XML reader parses the XML results file generated when you use the kwcheck desktop
 * program to export local desktop results to an XML file. The command is: kwcheck -F xml -- report
 * YOURFILENAME.xml.
 */
public class KlocworkXMLReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        /*
         * XML file starts with:
         *    <?xml version="1.0" encoding="UTF-8"?>
         *    <errorList xmlns="http://www.klocwork.com/inForce/report/1.0">
         *    <problem>
         */
        return resultFile.filename().endsWith(".xml")
                && resultFile.line(1).contains("klocwork")
                && resultFile.line(1).contains("inForce");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Klocwork", true, TestSuiteResults.ToolType.SAST);

        List<Node> problems = getNamedChildren("problem", resultFile.xmlRootNode());

        for (Node problem : problems) {
            TestCaseResult tcr = new TestCaseResult();
            String filename = getNamedChild("file", problem).getTextContent();
            if (isTestCaseFile(filename)) {
                tcr.setActualResultTestID(TestSuiteResults.getFileNameNoPath(filename));
                String category = getNamedChild("code", problem).getTextContent();
                tcr.setCWE(KlocworkCSVReader.cweLookup(category));
                tcr.setEvidence(category);

                int cwe = tcr.getCWE();
                if (cwe != CweNumber.DONTCARE && cwe != CweNumber.UNMAPPED) {
                    tr.put(tcr);
                }
            }
        }
        return tr;
    }
}
