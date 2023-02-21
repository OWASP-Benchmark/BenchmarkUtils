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
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

public class NoisyCricketReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("noisycricket");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("NoisyCricket", false, TestSuiteResults.ToolType.SAST);
        tr.setTime("1 minute");
        Node meta = getNamedChild("meta", resultFile.xmlRootNode());
        tr.setToolVersion(getAttributeValue("version", meta));

        Node vulns = getNamedChild("vulnerabilities", resultFile.xmlRootNode());
        List<Node> items = getNamedChildren("vulnerability", vulns);
        for (Node item : items) {
            try {
                parseNoisyCricketIssue(item, tr);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return tr;
    }

    private void parseNoisyCricketIssue(Node item, TestSuiteResults tr) {
        String testcase = getAttributeValue("file", item);

        String cwelist = getAttributeValue("cwelist", item);
        System.out.println(cwelist);
        cwelist = cwelist.substring(1, cwelist.length() - 1);
        if (!cwelist.isEmpty()) {
            String[] cwes = cwelist.split(", ");
            for (String cwe : cwes) {
                TestCaseResult tcr = new TestCaseResult();
                tcr.setNumber(testNumber(testcase));
                tcr.setCWE(Integer.parseInt(cwe));
                tr.put(tcr);
            }
        }
    }
}
