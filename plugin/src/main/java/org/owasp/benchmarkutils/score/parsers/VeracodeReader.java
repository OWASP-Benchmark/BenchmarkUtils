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

import java.io.FileInputStream;
import java.text.SimpleDateFormat;
import java.util.List;
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

public class VeracodeReader extends Reader {

    // submitted_date="2015-05-23 00:04:57 UTC"
    // published_date="2015-05-28 15:28:35 UTC"
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss zzz");

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && (resultFile.xmlRootNodeName().equalsIgnoreCase("detailedreport"));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {


        TestSuiteResults tr =
                new TestSuiteResults("Veracode SAST", true, TestSuiteResults.ToolType.SAST);

        // <static-analysis rating="F" score="24" submitted_date="2015-05-23 00:04:57 UTC"
        // published_date="2015-05-28 15:28:35 UTC" next_scan_due="2015-08-28 15:28:35 UTC"
        // analysis_size_bytes="70797465" engine_version="82491">
        Node root = resultFile.xmlRootNode();
        NodeList rootList = root.getChildNodes();
        Node sa = getNamedNode("static-analysis", rootList);
        String version = getAttributeValue("engine_version", sa);
        tr.setToolVersion(version);
        String submitted = getAttributeValue("submitted_date", sa);
        String published = getAttributeValue("published_date", sa);
        String time = calculateTime(submitted, published);
        tr.setTime(time);

        List<Node> sevList = getNamedNodes("severity", rootList);

        List<Node> catList = getNamedChildren("category", sevList);

        List<Node> cweList = getNamedChildren("cwe", catList);

        List<Node> statList = getNamedChildren("staticflaws", cweList);

        List<Node> flawList = getNamedChildren("flaw", statList);

        for (Node flaw : flawList) {
            TestCaseResult tcr = parseVeracodeVulnerability(flaw);
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private String calculateTime(String submitted, String published) {
        try {
            long start = sdf.parse(submitted).getTime();
            long finish = sdf.parse(published).getTime();
            return TestSuiteResults.formatTime(finish - start);
        } catch (Exception e) {
            return "Unknown";
        }
    }

    private TestCaseResult parseVeracodeVulnerability(Node flaw) {
        TestCaseResult tcr = new TestCaseResult();

        /**
         * [affects_policy_compliance="true", categoryid="18", categoryname="Improper Neutralization
         * of Special Elements used in an OS Command ('OS Command Injection')", cia_impact="ccp",
         * count="1", cweid="78", date_first_occurrence="2015-05-21 04:27:14 UTC", description=" ",
         * exploitLevel="2", functionprototype="void doPost(javax.servlet.http.HttpServletRequest,
         * javax.servlet.http.HttpServletResponse)", functionrelativelocation="85",
         * grace_period_expires="2015-05-28 15:28:35 UTC", issueid="4234", line="81",
         * mitigation_status="none", mitigation_status_desc="Not Mitigated", module="Class files
         * within benchmark_classes-1.1.zip", note="", pcirelated="true", remediation_status="New",
         * remediationeffort="3", scope="org.owasp.benchmark.testcode.BenchmarkTest00020",
         * severity="5", sourcefile="BenchmarkTest00020.java",
         * sourcefilepath="org/owasp/benchmark/testcode/", type="java.lang.Runtime.exec"]
         */
        String cwe = getAttributeValue("cweid", flaw);
        if (cwe != null) {
            tcr.setCWE(translate(Integer.parseInt(cwe)));
        } else {
            System.out.println("flaw: " + flaw);
        }

        tcr.setCategory(getAttributeValue("categoryname", flaw));

        tcr.setConfidence(Integer.parseInt(getAttributeValue("exploitLevel", flaw)));

        tcr.setEvidence(getAttributeValue("categoryname", flaw));

        String testcase = getAttributeValue("sourcefile", flaw);
        if (testcase.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(testcase));
            return tcr;
        }

        return null;
    }

    private int translate(int cwe) {
        if (cwe == 73) return 22;
        if (cwe == 80) return 79;
        if (cwe == 331) return 330;
        if (cwe == 91) return 643;
        return cwe;
    }
}
