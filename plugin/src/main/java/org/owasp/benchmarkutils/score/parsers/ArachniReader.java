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
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2015
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
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
import org.xml.sax.InputSource;

public class ArachniReader extends Reader {

    // 2015-08-17T14:21:14+03:00
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.line(1).contains("Arachni")
                && !resultFile
                        .xmlRootNodeName()
                        .equals("BugCollection"); // Ignore Find(Sec)Bugs files
    }

    //    <report xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    // xsi:noNamespaceSchemaLocation="https://raw.githubusercontent.com/Arachni/arachni/v2.0dev/components/reporters/xml/schema.xsd">
    //    <version>2.0dev</version>
    //    <start_datetime>2015-08-17T14:21:14+03:00</start_datetime>
    //    <finish_datetime>2015-08-17T14:44:14+03:00</finish_datetime>
    //    <sitemap>

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr =
                new TestSuiteResults("Arachni", false, TestSuiteResults.ToolType.DAST);

        Node arachni = doc.getDocumentElement();
        String version = getNamedChild("version", arachni).getTextContent();
        tr.setToolVersion(version);

        String start = getNamedChild("start_datetime", arachni).getTextContent();
        String stop = getNamedChild("finish_datetime", arachni).getTextContent();
        tr.setTime(calculateTime(start, stop));

        Node issues = getNamedChild("issues", arachni);
        List<Node> issueList = getNamedChildren("issue", issues);

        for (Node issue : issueList) {
            try {
                TestCaseResult tcr = parseArachniIssue(issue);
                if (tcr != null) {
                    //                 System.out.println( tcr.getNumber() + " " + tcr.getName() + "
                    // -> " + tcr.getCWE() + "\t" + tcr.getEvidence() );
                    tr.put(tcr);
                }
            } catch (Exception e) {
                // print and continue
                e.printStackTrace();
            }
        }
        return tr;
    }

    //    <issue>
    //    <name>Cross-Site Scripting (XSS)</name>
    //    <description>
    // Client-side scripts are used extensively by modern web applications.
    // </description>
    //    <remedy_guidance>
    // </remedy_guidance>
    //    <remedy_code/>
    //    <severity>high</severity>
    //    <check>
    //      <name>XSS</name>
    //      <description>
    // Injects an HTML element into page inputs and then parses the HTML markup of
    // </description>
    //      <author>Tasos "Zapotek" Laskos &lt;tasos.laskos@arachni-scanner.com&gt; </author>
    //      <version>0.4.4</version>
    //      <shortname>xss</shortname>
    //    </check>
    //    <cwe>79</cwe>
    //    <digest>3396861445</digest>
    //    <references>
    //    </references>
    //    <vector>
    //      <class>Arachni::Element::Form</class>
    //      <type>form</type>
    //      <url>https://127.0.0.2:8443/benchmark/BenchmarkTest00397.html</url>
    //      <action>https://127.0.0.2:8443/benchmark/BenchmarkTest00397</action>
    //      <source>/form&gt;</source>
    //      <method>post</method>
    //      <affected_input_name>vector</affected_input_name>
    //      <inputs>
    //        <input name="vector" value="Singing"/>
    //        <input name="foo" value="bar"/>
    //      </inputs>
    //    </vector>
    //  </issue>

    private String calculateTime(String submitted, String published) {
        try {
            long start = sdf.parse(submitted).getTime();
            long finish = sdf.parse(published).getTime();
            return TestSuiteResults.formatTime(finish - start);
        } catch (Exception e) {
            e.printStackTrace();
            return "Unknown";
        }
    }

    private TestCaseResult parseArachniIssue(Node flaw) throws URISyntaxException {
        TestCaseResult tcr = new TestCaseResult();
        Node rule = getNamedChild("cwe", flaw);
        if (rule != null) {
            tcr.setCWE(cweLookup(rule.getTextContent()));
        }

        String cat = getNamedChild("name", flaw).getTextContent();
        tcr.setCategory(cat);

        // not used
        // String conf = getNamedChild( "severity", flaw ).getTextContent();

        // confidence not available
        // tcr.setConfidence( Integer.parseInt( conf ) );

        tcr.setEvidence(cat);

        Node vector = getNamedChild("vector", flaw);
        String uri = getNamedChild("url", vector).getTextContent();
        URI url = new URI(uri);
        String testfile = url.getPath();
        testfile = testfile.substring(testfile.lastIndexOf('/') + 1);

        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(testfile));
            return tcr;
        }
        return null;
    }

    private int cweLookup(String orig) {
        return Integer.parseInt(orig);
    }
}
