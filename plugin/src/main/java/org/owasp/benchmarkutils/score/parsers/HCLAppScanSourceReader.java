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
 * @created 2018
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.FileInputStream;
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

// This is the new HCL AppScan Source reader, where they generate ".xml" files.
// The 'old' reader is AppScanSourceReader, which supports the previous .ozasmt format from IBM.

public class HCLAppScanSourceReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("xml-report")
                && "AppScan Report".equals(getAttributeValue("name", resultFile.xmlRootNode()))
                && "SAST".equals(getAttributeValue("technology", resultFile.xmlRootNode()));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(resultFile.file()));
        Document doc = docBuilder.parse(is);

        Node root = doc.getDocumentElement();
        Node scanInfo = getNamedChild("scan-information", root);
        TestSuiteResults tr =
                new TestSuiteResults("IBM AppScan Cloud", true, TestSuiteResults.ToolType.SAST);

        Node version = getNamedChild("product-version", scanInfo);
        //    System.out.println("Product version is: " + version.getTextContent());
        tr.setToolVersion(version.getTextContent());

        // If the fliename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml) set the
        // compute time on the scorecard.
        tr.setTime(resultFile.file());

        Node allIssues = getNamedChild("issue-group", root);
        List<Node> vulnerabilities = getNamedChildren("item", allIssues);

        // Loop through all the vulnerabilities
        for (Node vulnerability : vulnerabilities) {

            // First get the type of vuln, and if we don't care about that type, move on
            String issueType =
                    getNamedChild("ref", getNamedChild("issue-type", vulnerability))
                            .getTextContent();

            int vtype = cweLookup(issueType);
            //	System.out.println("Vuln type: " + issueType + " has CWE of: " + vtype);

            // Then get the filename containing the vuln. And if not in a test case, skip it.
            Node itemNode = getNamedChild("item", getNamedChild("variant-group", vulnerability));
            Node methodSigNode =
                    getNamedChild(
                            "method-signature2", getNamedChild("issue-information", itemNode));
            int tn = -1; // -1 means vuln not found in a Benchmark test case
            if (methodSigNode != null) {

                String filename = getAttributeValue("filename", methodSigNode);

                // Some method signatures have a filename attribute, others do not, depending on the
                // vuln type.
                if (filename != null) {
                    // Parse out test number from: BenchmarkTest02603:99
                    if (filename.startsWith(BenchmarkScore.TESTCASENAME)) {
                        tn = testNumber(filename);
                        // filename = filename.substring(0, filename.indexOf(":"));
                        // String testnum =
                        // filename.substring(BenchmarkScore.TESTCASENAME.length());
                        // tn = Integer.parseInt(testnum);

                        // System.out.println("Found a result in filename for test: " + tn);
                    }
                } else {
                    // Parse out test # from:
                    // org.owasp.benchmark.testcode.BenchmarkTest01484.doPost(HttpServletRequest;HttpServletResponse):void
                    String methodSig = methodSigNode.getTextContent();
                    if (methodSig != null && methodSig.contains(BenchmarkScore.TESTCASENAME)) {
                        String s =
                                methodSig.substring(
                                        methodSig.indexOf(BenchmarkScore.TESTCASENAME)
                                                + BenchmarkScore.TESTCASENAME.length());
                        tn = testNumber(s);
                        // String testnum = s.substring(0, s.indexOf("."));
                        // tn = Integer.parseInt(testnum);
                        // System.out.println("Found a result in method location2 for test: " + tn);
                    }
                    // else System.out.println("Didn't find Benchmark test case in method
                    // signature2: " + methodSig);
                    else if (methodSig == null)
                        System.out.println("itemNode: " + itemNode + " has no method signature2");
                }
            } else System.out.println("itemNode: " + itemNode + " has no method signature node");

            //			if (tn == -1) System.out.println("Found vuln outside of test case of type: " +
            // issueType);

            // Add the vuln found in a test case to the results for this tool
            TestCaseResult tcr = new TestCaseResult();
            tcr.setNumber(tn);
            tcr.setCategory(issueType); // TODO: Is this right?
            tcr.setCWE(vtype);
            tcr.setEvidence(issueType);
            //				tcr.setConfidence( confidence );

            // Exclude Confidence 3 - apparently these are "scan coverage"
            // We tried excluding Confidence 2 as well - as these are "suspect", but AppScan's score
            // actually
            // went down because it excludes ALL of the weak randomness findings.
            // Confidence 1 - are "definitive" findings
            //				if ( confidence < 3 ) {
            tr.put(tcr);
            //				}
        }
        return tr;
    }

    // e.g., 3 Hour(s) 7 Minute(s) 58 Second(s)
    /*	private String parseTime(String message) {
    	    String[] parts = message.split( "\\) ");
            String hours = parts[0].substring( 0, parts[0].indexOf(' ') ).trim();
            if ( hours.length() < 2 ) hours = "0" + hours;
            String mins = parts[1].substring( 0, parts[1].indexOf(' ') ).trim();
            if ( mins.length() < 2 ) mins = "0" + mins;
            String secs = parts[2].substring( 0, parts[2].indexOf(' ') ).trim();
            if ( secs.length() < 2 ) secs = "0" + secs;
    	    return hours + ":" + mins + ":" + secs;
        }
    */
    private int cweLookup(String vtype) {
        switch (vtype) {
                //			case "AppDOS" : return 00;
                //			case "Authentication.Entity" : return 00;

            case "CrossSiteScripting":
            case "Validation.EncodingRequired":
                return CweNumber.XSS;
            case "Cryptography.InsecureAlgorithm":
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "Cryptography.PoorEntropy":
                return CweNumber.WEAK_RANDOM;
                //			case "Cryptography.????WeakHash" : return 328;  // They don't have a weak
                // hashing rule

                //			case "ErrorHandling.RevealDetails.Message" : return 00;
                //			case "ErrorHandling.RevealDetails.StackTrace" : return 00;
            case "Injection.HttpResponseSplitting":
                return CweNumber.HTTP_RESPONSE_SPLITTING;
            case "Injection.LDAP":
                return CweNumber.LDAP_INJECTION;
            case "Injection.OS":
                return CweNumber.COMMAND_INJECTION;
            case "Injection.SQL":
                return CweNumber.SQL_INJECTION;
            case "Injection.XPath":
                return CweNumber.XPATH_INJECTION;
                //			case "Malicious.DynamicCode" : return 00;
                //			case "Malicious.DynamicCode.Execution" : return 00;
            case "OpenSource":
                return 00; // Known vuln in open source lib.
            case "PathTraversal":
                return CweNumber.PATH_TRAVERSAL;
                //			case "Quality.TestCode" : return 00;
                //			case "Quality.Unsupported" : return 00;
            case "SessionManagement.Cookies":
                return CweNumber.INSECURE_COOKIE;
            case "Validation.Required":
            case "Validation.Required.WriteToStream":
                return CweNumber.INSECURE_DESERIALIZATION;

            default:
                System.out.println(
                        "WARNING: HCL AppScan Source-Unrecognized finding type: " + vtype);
        }
        return 0;
    }
}
