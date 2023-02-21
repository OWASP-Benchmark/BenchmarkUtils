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
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class ParasoftReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.line(1).startsWith("<ResultsSession");
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
                new TestSuiteResults("Parasoft Jtest", true, TestSuiteResults.ToolType.SAST);

        Node root = doc.getDocumentElement();

        // <ResultsSession time="06/03/15 10:10:09" toolName="Jtest" toolVer="9.5.13.20140908>
        String version = getAttributeValue("toolVer", root);
        tr.setToolVersion(version);

        NodeList rootList = root.getChildNodes();
        List<Node> stds = getNamedNodes("CodingStandards", rootList);
        Node std = stds.get(0);
        String time = getAttributeValue("time", std);
        tr.setTime(time);

        List<Node> viols = getNamedChildren("StdViols", stds);

        List<Node> stdList = getNamedChildren("StdViol", viols);

        List<Node> flowList = getNamedChildren("FlowViol", viols);

        for (Node flaw : stdList) {
            TestCaseResult tcr = parseStdViol(flaw);
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        for (Node flaw : flowList) {
            TestCaseResult tcr = parseFlowViol(flaw);
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private TestCaseResult parseStdViol(Node flaw) {
        // <StdViol sev="2" ln="49" cat="SECURITY.IBA" hash="395273668" tool="jtest" locType="sr"
        // msg="'getName()' is a dangerous data-returning method and should be encapsulated by a
        // validation"
        // lang="java" rule="SECURITY.IBA.VPPD" config="1" auth="kupsch" locOffs="1749" locLen="7"
        // locFile="/temp/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java" />

        TestCaseResult tcr = new TestCaseResult();
        String cat = getAttributeValue("cat", flaw);
        if (cat == null) {
            String rule = getAttributeValue("rule", flaw);
            int idx = rule.lastIndexOf('.');
            if (idx != -1) {
                cat = rule.substring(0, idx);
            }
        }

        if (cat != null) {
            tcr.setCWE(cweLookup(cat));
            tcr.setCategory(getAttributeValue("rule", flaw));
            tcr.setConfidence(Integer.parseInt(getAttributeValue("sev", flaw)));
            tcr.setEvidence(getAttributeValue("msg", flaw));

            String testcase = getAttributeValue("locFile", flaw);
            testcase = testcase.substring(testcase.lastIndexOf('/'));
            if (testcase.startsWith(BenchmarkScore.TESTCASENAME)) {
                tcr.setNumber(testNumber(testcase));
                return tcr;
            }
        }
        return null;
    }

    private TestCaseResult parseFlowViol(Node flaw) {
        // <FlowViol sev="1" ln="64" hash="-1497144802" ruleSCSCMsg="Tainting Point" tool="jtest"
        // locType="sr" sym="=TempProject/java&lt;org.owasp.benchmark.testcode" lang="java"
        // msg="Injection of data received from servlet request (&quot;param&quot;) to filename
        // setting method"
        // id="924224628" rule="BD.SECURITY.TDFNAMES" config="1" dumpId="37" ruleSAFMsg="Dangerous
        // Method Call"
        // auth="kupsch" FirstElSrcRngOffs="1570" FirstElSrcRngLen="30"
        // FirstElSrcRngFile="/temp/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java"
        // locOffs="1970" locLen="95"
        // locFile="/temp/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java">

        TestCaseResult tcr = new TestCaseResult();
        String cat = getAttributeValue("rule", flaw);
        tcr.setCWE(cweLookup(cat));

        String rule = getAttributeValue("rule", flaw);
        tcr.setCategory(rule);

        String severity = getAttributeValue("sev", flaw);
        tcr.setConfidence(Integer.parseInt(severity));

        String msg = getAttributeValue("msg", flaw);
        tcr.setEvidence(msg);

        String testcase = getAttributeValue("locFile", flaw);
        testcase = testcase.substring(testcase.lastIndexOf('/') + 1);
        if (testcase.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(testcase));
            return tcr;
        }
        return null;
    }

    // https://www.securecoding.cert.org/confluence/display/java/Parasoft
    private int cweLookup(String cat) {

        switch (cat) {
                //        case "BD.PB.CC" : return x;
                //        case "BD.RES.LEAKS" : return x;
            case "BD.SECURITY.TDCMD":
                return CweNumber.COMMAND_INJECTION;
            case "BD.SECURITY.TDFNAMES":
                return CweNumber.PATH_TRAVERSAL;
            case "BD.SECURITY.TDLDAP":
                return CweNumber.LDAP_INJECTION;
                //        case "BD.SECURITY.TDNET" : return x;
                //        case "BD.SECURITY.TDRESP" : return x;
            case "BD.SECURITY.TDSQL":
                return CweNumber.SQL_INJECTION;
            case "BD.SECURITY.TDXPATH":
                return CweNumber.XPATH_INJECTION;
            case "BD.SECURITY.TDXSS":
                return CweNumber.XSS;
                //        case "INTER" : return x;
                //        case "JDBC" : return x;
                //        case "OPT" : return x;
                //        case "SECURITY.IBA" : return x;
                //        case "SECURITY.WSC" : return x;
                //        case "TRS" : return x;

                //        case "Cookie Security" : return 614;
                //        case "Header Manipulation" : return 113;
            case "SECURITY.WSC.SRD":
                return CweNumber.WEAK_RANDOM;
                //        case "Password Management" : return 00;
                //        case "Trust Boundary Violation" : return 501;
                //        case "Weak Cryptographic Hash" : return 328;
                //        case "Weak Encryption" : return 327;
        }
        return -1;
    }
}
