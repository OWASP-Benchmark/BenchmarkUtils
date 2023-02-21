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
import org.xml.sax.InputSource;

public class CheckmarxReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.line(1).startsWith("<CxXMLResults");
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
                new TestSuiteResults("Checkmarx CxSAST", true, TestSuiteResults.ToolType.SAST);

        // <CxXMLResults
        // DeepLink="http://CHECKMARX2/CxWebClient/ViewerMain.aspx?scanid=52869&amp;projectid=30265"
        // ScanStart="Monday, July 27, 2015 4:50:08 PM" Preset="Default 2014" ScanTime="13h:54m:20s"
        // LinesOfCodeScanned="1507279" FilesScanned="21075" ReportCreationTime="Tuesday, July 28,
        // 2015 8:38:30 AM"
        // Team="CxServer" CheckmarxVersion="7.1.8 HF2" ScanComments="" ScanType="Full"
        // SourceOrigin="LocalPath">

        Node root = doc.getDocumentElement();
        String version = getAttributeValue("CheckmarxVersion", root);
        tr.setToolVersion(version);

        String time = getAttributeValue("ScanTime", root);
        tr.setTime(time);

        List<Node> queryList = getNamedChildren("Query", root);

        for (Node query : queryList) {
            List<Node> resultList = getNamedChildren("Result", query);
            for (Node result : resultList) {
                try {
                    TestCaseResult tcr = parseCheckmarxVulnerability(query, result);
                    if (tcr != null) {
                        tr.put(tcr);
                    }
                } catch (Exception e) {
                    System.out.println(">> Error detected. Attempting to continue parsing");
                    e.printStackTrace();
                }
            }
        }
        return tr;
    }

    private TestCaseResult parseCheckmarxVulnerability(Node query, Node result) {
        TestCaseResult tcr = new TestCaseResult();
        // <Query id="594" cweId="89" name="SQL_Injection" group="Java_High_Risk" Severity="High"
        // Language="Java" LanguageHash="0188428345217368"
        // LanguageChangeDate="2015-07-14T00:00:00.0000000"
        // SeverityIndex="3">

        // <Result NodeId="528692318"
        // FileName="/org/owasp/benchmark/testcode/BenchmarkTest00026.java"
        // Status="New" Line="50" Column="29" FalsePositive="False" Severity="High" AssignToUser=""
        // state="0" Remark=""
        // DeepLink="http://CHECKMARX2/CxWebClient/ViewerMain.aspx?scanid=52869&amp;projectid=30265&amp;pathid=2318"
        // SeverityIndex="3">

        String cwe = getAttributeValue("cweId", query);
        if (cwe != null) {
            tcr.setCWE(translate(Integer.parseInt(cwe)));
        } else {
            System.out.println("flaw: " + query);
        }

        String name = getAttributeValue("name", query);
        tcr.setCategory(name);
        // filter out dynamic SQL queries because they report SQL injection separately - these are
        // just dynamic SQL
        // Other queries are filtered because they are a CHILD_OF of some other query and they share
        // the same cwe id
        // We only want the results from the queries that are relevant (PARENT_OF) for the benchmark
        // project
        if (name.equals("Dynamic_SQL_Queries")
                || name.equals("Heuristic_2nd_Order_SQL_Injection")
                || name.equals("Heuristic_SQL_Injection")
                || name.equals("Second_Order_SQL_Injection")
                || name.equals("Blind_SQL_Injections")
                || name.equals("Improper_Build_Of_Sql_Mapping")
                || name.equals("SQL_Injection_Evasion_Attack")
                || name.equals("Potential_SQL_Injection")
                || name.equals("Client_Side_Injection")
                || name.equals("GWT_DOM_XSS")
                || name.equals("GWT_Reflected_XSS")
                || name.equals("Heuristic_CGI_Stored_XSS")
                || name.equals("Heuristic_Stored_XSS")
                || name.equals("Stored_XSS")
                || name.equals("Suspected_XSS")
                || name.equals("UTF7_XSS")
                || name.equals("CGI_Stored_XSS")
                || name.equals("Potential_GWT_Reflected_XSS")
                || name.equals("Potential_I_Reflected_XSS_All_Clients")
                || name.equals("Potential_IO_Reflected_XSS_All_Clients")
                || name.equals("Potential_O_Reflected_XSS_All_ClientsS")
                || name.equals("Potential_Stored_XSS")
                || name.equals("Potential_UTF7_XSS")
                || name.equals("Stored_Command_Injection")
                || name.equals("CGI_Reflected_XSS_All_Clients")
                || name.equals("Unprotected_Cookie")) {
            return null;
        }

        // Output xml file from Checkmarx (depends on version) sometimes does not contain attribute
        // on the node "query" named SeverityIndex
        String SeverityIndex = getAttributeValue("SeverityIndex", result);
        boolean isGeneratedByCxWebClient = SeverityIndex != null && !SeverityIndex.equals("");
        if (isGeneratedByCxWebClient) {
            tcr.setConfidence(Integer.parseInt(getAttributeValue("SeverityIndex", result)));
        }

        tcr.setEvidence(getAttributeValue("name", query));

        /* Some results do not appear in the previous version of this parser because it only look for the attribute "FileName"
         *  Checkmarx have some results where the input does not start in a BenchmarkTest file so it was necessary to make some changes
         *  We must consider a good result if the result node "FileName" startsWith BenchmarkTest file or if the last PathNode ends in a "FileName" that startsWith BenchmarkTest file.
         *  An example is the SeparateClassRequest.java file that have some inputs that we catch but are not been considered as a valid result (FN)
         */

        // Get the Path element inside Result
        List<Node> paths = getNamedChildren("Path", result);
        // Get ALL the PathNodes elements inside each Path
        List<Node> pathNodes = getNamedChildren("PathNode", paths.get(0));
        // Get the lAST PathNode element from the list above
        Node last = pathNodes.get(pathNodes.size() - 1);
        // Get the FileName element inside the last PathNode
        List<Node> fileNames = getNamedChildren("FileName", last);
        Node fileNameNode = fileNames.get(0);

        // If the result starts in a BenchmarkTest file
        String testcase = getAttributeValue("FileName", result);
        // Output xml file from Checkmarx (depends on version) may use windows based '\\' or unix
        // based '/' delimiters for path
        if (isGeneratedByCxWebClient) {
            testcase = testcase.substring(testcase.lastIndexOf('/') + 1);
        } else {
            testcase = testcase.substring(testcase.lastIndexOf('\\') + 1);
        }
        if (testcase.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(testcase));
            return tcr;
        } else {
            // If not, then the last PastNode must end in a FileName that startsWith BenchmarkTest
            // file
            // Skipping nodes with no filename specified <FileName></FileName>
            if (fileNameNode.getFirstChild() == null) return null;

            String testcase2 = fileNameNode.getFirstChild().getNodeValue();
            // Output xml file from Checkmarx (depends on version) may use windows based '\\' or
            // unix based '/' delimiters for path
            if (isGeneratedByCxWebClient) {
                testcase2 = testcase2.substring(testcase2.lastIndexOf('/') + 1);
            } else {
                testcase2 = testcase2.substring(testcase2.lastIndexOf('\\') + 1);
            }
            if (testcase2.startsWith(BenchmarkScore.TESTCASENAME)) {
                tcr.setNumber(testNumber(testcase2));
                return tcr;
            }
        }

        return null;
    }

    private int translate(int cwe) {
        switch (cwe) {
            case 77:
            case 15:
                return CweNumber.COMMAND_INJECTION;
            case 36:
            case 23:
                return CweNumber.PATH_TRAVERSAL;
            case 338:
                return CweNumber.WEAK_RANDOM;
        }
        return cwe;
    }
}
