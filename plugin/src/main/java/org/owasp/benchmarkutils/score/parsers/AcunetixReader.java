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

import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

public class AcunetixReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && (resultFile.xmlRootNodeName().equals("ScanGroup")
                        || resultFile.xmlRootNodeName().equals("acunetix-360"));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        if (resultFile.xmlRootNodeName().equalsIgnoreCase("acunetix-360")) {

            /* This is for the 2020 format that looks like:
            	 <acunetix-360 generated="28/02/2020 08:59 AM">
            		<target>
            			<scan-id>f55650d3326f40f30d92ab6e04af1794</scan-id>
            			<url>https://localhost:8443/benchmark/</url>
            			<initiated>27/02/2020 04:49 PM</initiated>
            			<duration>01:57:21.2094646</duration>
            		</target>
            		<vulnerabilities>
            			<vulnerability>
            				<LookupId>cf5644f1-31ee-4092-0e15-ab6e04af7f51</LookupId>
            				...
            */
            TestSuiteResults tr =
                    new TestSuiteResults("Acunetix 360", true, TestSuiteResults.ToolType.DAST);

            Node target = getNamedChild("target", resultFile.xmlRootNode());
            String duration = getNamedChild("duration", target).getTextContent();
            // duration format is: 01:57:21.2094646
            tr.setTime(duration.substring(0, duration.lastIndexOf('.')));

            Node issues = getNamedChild("vulnerabilities", resultFile.xmlRootNode());
            List<Node> issueList = getNamedChildren("vulnerability", issues);

            for (Node issue : issueList) {
                try {
                    TestCaseResult tcr = parseAcunetixVulnerability(issue);
                    if (tcr != null) {
                        tr.put(tcr);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            return tr;

        } else if (resultFile.xmlRootNodeName().equalsIgnoreCase("ScanGroup")) {

            // The following is for the legacy format that looks like so:

            /*  <ScanGroup ExportedOn="11/9/2015, 21:42">
                  <Scan>
                    <ReportItems>
                      <ReportItem>
                       <Name><![CDATA[Scan Thread 1 ( https://172.16.11.1:8443/benchmark/ )]]></Name>
                       <ShortName><![CDATA[Scan Thread 1]]></ShortName>
                       <StartURL><![CDATA[https://172.16.11.1:8443/benchmark/]]></StartURL>
                       <StartTime><![CDATA[11/9/2015, 14:50:33]]></StartTime>
                       <FinishTime><![CDATA[11/9/2015, 15:31:02]]></FinishTime>
                       <ScanTime><![CDATA[40 minutes, 29 seconds]]></ScanTime>

                      </ReportItem>
                    </ReportItems>
                  </Scan>
                </ScanGroup>
            */
            TestSuiteResults tr =
                    new TestSuiteResults("Acunetix WVS", true, TestSuiteResults.ToolType.DAST);
            Node scan = getNamedChild("Scan", resultFile.xmlRootNode());

            String duration = getNamedChild("ScanTime", scan).getTextContent();
            tr.setTime(duration);

            Node issues = getNamedChild("ReportItems", scan);

            for (Node issue : getNamedChildren("ReportItem", issues)) {
                try {
                    TestCaseResult tcr = parseAcunetixReportItem(issue);
                    if (tcr != null) {
                        tr.put(tcr);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            return tr;
        } // end if (root.getNodeName().equalsIgnoreCase("ScanGroup")) - Legacy format
        else
            System.out.println(
                    "XML file didn't match expected Acunetix format. Expected <acunetix-360"
                            + " or <ScanGroup ExportedOn ... to be first XML tag in file.");
        return null;
    } // end parse()

    /* The Acunetix 360 <vulnerability> format:
         <vulnerability>
            <LookupId>cf5644f1-31ee-4092-0e15-ab6e04af7f51</LookupId>
            <url>https://localhost:8443/benchmark/</url>
            <type>InvalidSslCertificate</type>
              ...
            <classification>
              <owasp>A6</owasp>
              <wasc>4</wasc>
              <cwe>295</cwe>
                ...

    */

    private TestCaseResult parseAcunetixVulnerability(Node vuln) throws Exception {
        TestCaseResult tcr = new TestCaseResult();

        String uri = getNamedChild("url", vuln).getTextContent();
        String testfile = uri.substring(uri.lastIndexOf('/') + 1);
        if (testfile.contains("?")) {
            testfile = testfile.substring(0, testfile.indexOf("?"));
        }
        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(testfile));
            String cat = getNamedChild("type", vuln).getTextContent();
            tcr.setCategory(cat);

            Node classification = getNamedChild("classification", vuln);
            Node vulnId = getNamedChild("cwe", classification);
            if (vulnId != null) {
                String cweNum = vulnId.getTextContent();
                int cwe = cweLookup(cweNum);
                tcr.setCWE(cwe);
                // System.out.println("Found CWE: " + cwe + " in test case: " +
                // tcr.getNumber());
                tcr.setConfidence(
                        Integer.parseInt(getNamedChild("certainty", vuln).getTextContent()));
                return tcr;
            }
        }

        return null;
    }

    //  This is the legacy <ReportItem> format:
    //    <ReportItem id="0" color="orange">
    //    <Name><![CDATA[HTML form without CSRF protection]]></Name>
    //    <Details><![CDATA[Form name: <font color="navy">&lt;empty&gt;</font><br/>Form action:
    // <font color="navy">https://172.16.11.1:8443/benchmark/BenchmarkTest01925</font><br/>Form
    // method: <font color="navy">POST</font><br/><br/>Form inputs:<br/><ul><li>vectorArea
    // [TextArea]</li><li>answer [Text]</li><li>vector [Text]</li></ul>]]></Details>
    //    <Affects><![CDATA[/benchmark/BenchmarkTest01925.html]]></Affects>
    //    <IsFalsePositive><![CDATA[False]]></IsFalsePositive>
    //    <Severity><![CDATA[medium]]></Severity>
    //    <CWE id="352"><![CDATA[CWE-352]]></CWE>
    //  This is the newer <ReportItem> format
    //    <CWEList>
    //      <CWE id="352"><![CDATA[CWE-352]]></CWE>
    //    </CWEList>

    private TestCaseResult parseAcunetixReportItem(Node flaw) throws Exception {
        TestCaseResult tcr = new TestCaseResult();

        String cat = getNamedChild("Name", flaw).getTextContent();
        tcr.setCategory(cat);
        tcr.setEvidence(cat);

        Node cweList = getNamedChild("CWEList", flaw);
        Node vulnId = getNamedChild("CWE", cweList != null ? cweList : flaw);
        if (vulnId != null) {
            String cweNum = getAttributeValue("id", vulnId);
            int cwe = cweLookup(cweNum, cat);
            tcr.setCWE(cwe);
        }

        //        String conf = getNamedChild( "Severity", flaw ).getTextContent();
        //        tcr.setConfidence( Integer.parseInt( conf ) );

        String uri = getNamedChild("Affects", flaw).getTextContent();
        int spaceIdx = uri.indexOf(' ');
        if (spaceIdx != -1) {
            uri = uri.substring(0, spaceIdx);
        }
        String testfile = uri.substring(uri.lastIndexOf('/') + 1);
        if (testfile.contains("?")) {
            testfile = testfile.substring(0, testfile.indexOf("?"));
        }

        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(testfile));
            return tcr;
        }
        return null;
    }

    private int cweLookup(String cweNum) {
        if (cweNum == null || cweNum.isEmpty()) {
            System.out.println("ERROR: No CWE number supplied");
            return 0000;
        }
        return cweLookup(cweNum, null);
    }

    private int cweLookup(String cweNum, String name) {
        if (cweNum == null || cweNum.isEmpty()) {
            System.out.println("ERROR: No CWE number supplied");
            return 0000;
        }
        switch (cweNum) {
            case "22":
                return CweNumber.PATH_TRAVERSAL;
            case "78":
                return CweNumber.COMMAND_INJECTION;
            case "79":
                return CweNumber.XSS;
            case "89":
                return CweNumber.SQL_INJECTION;
            case "614":
                return CweNumber.INSECURE_COOKIE;
            case "20":
                switch (name) {
                    case "LDAP injection":
                        return CweNumber.LDAP_INJECTION;
                    case "Server-side template injection":
                        return CweNumber.SSTI;
                }
                break;

                // switch left in case we ever need to map a reported cwe to the one expected by
                // Benchmark
                //        case "ldap-injection"            :  return 90;   // ldap injection
                //        case "header-injection"          :  return 113;  // header injection
                //        case "hql-injection"             :  return 0000; // hql injection
                //        case "unsafe-readline"           :  return 0000; // unsafe readline
                //        case "reflection-injection"      :  return 0000; // reflection injection
                //        case "xpath-injection"           :  return 643;  // xpath injection
                //        case "crypto-bad-mac"            :  return 328;  // weak hash
                //        case "crypto-weak-randomness"    :  return 330;  // weak random
                //        case "crypto-bad-ciphers"        :  return 327;  // weak encryption
                //        case "trust-boundary-violation"  :  return 501;  // trust boundary
                //        case "xxe"                       :  return 611;  // xml entity
            case "209": // Application error messages
                return CweNumber.DONTCARE;
            case "310": // TLS/SSL LOGJAM attack
                return CweNumber.DONTCARE;
            case "937": // Vulnerable JavaScript libraries
                return CweNumber.DONTCARE;
        }

        // Add any 'new' CWEs ever found to switch above so we know they are mapped properly.
        System.out.println("INFO: Found following CWE which we haven't seen before: " + cweNum);
        return Integer.parseInt(cweNum);
    }
}
