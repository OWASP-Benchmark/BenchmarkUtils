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

import java.io.StringReader;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;

// This is the new HCL AppScan DAST reader, where they generate ".xml" files. HCL calls this AppScan
// Standard.
// The 'old' reader is AppScanDynamicReader, which supports the previous .xml format from IBM.
public class HCLAppScanStandardReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("xml-report")
                && "AppScan Report".equals(getAttributeValue("name", resultFile.xmlRootNode()))
                && "DAST".equals(getAttributeValue("technology", resultFile.xmlRootNode()));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);

        Node root = doc.getDocumentElement();
        Node scanInfo = getNamedChild("scan-information", root);

        Node scanConfiguration = getNamedChild("scan-configuration", root);
        String startingUrl = getNamedChild("starting-url", scanConfiguration).getTextContent();

        TestSuiteResults tr =
                new TestSuiteResults("HCL AppScan Standard", true, TestSuiteResults.ToolType.DAST);

        // version is usually like 9.3.0 but sometimes like 9.3.0 iFix005. We trim off the part
        // after the space char.
        Node version = getNamedChild("product-version", scanInfo);
        //    System.out.println("Product version is: " + version.getTextContent());
        if (version != null) {
            tr.setToolVersion(version.getTextContent().split(" ")[0]);
        }

        Node allIssues = getNamedChild("url-group", root);
        List<Node> vulnerabilities = getNamedChildren("item", allIssues);

        Node allIssueVariants = getNamedChild("issue-group", root);
        List<Node> variants = getNamedChildren("item", allIssueVariants);

        // Loop through all the vulnerabilities
        for (Node vulnerability : vulnerabilities) {
            String issueType = getNamedChild("issue-type", vulnerability).getTextContent();

            String url = getNamedChild("name", vulnerability).getTextContent();
            // to give DAST tools some credit, if they report a similar vuln in a different area, we
            // count it.
            // e.g., SQLi in the XPATHi tests. To do that, we have to pull out the vuln type from
            // the URL.

            NamedNodeMap itemNode = vulnerability.getAttributes();
            String variantItemID = itemNode.getNamedItem("id").getNodeValue();

            List<String> testCaseElementsFromVariants =
                    variantLookup(issueType, variantItemID, startingUrl, variants);
            if (testCaseElementsFromVariants.isEmpty()) {
                // Handle non-variant issue types , Older xml format as in 9.x release versions and
                // before
                // First get the type of vuln, and if we don't care about that type, move on
                TestCaseResult tcr = TestCaseLookup(issueType, url);
                if (tcr != null) tr.put(tcr);
            } else {
                // Handle issues which are Variants, new xml format after 10.x release
                for (String testArea : testCaseElementsFromVariants) {
                    TestCaseResult tcr = TestCaseLookup(issueType, testArea);
                    if (tcr != null) tr.put(tcr);
                }
            }
        }

        return tr;
    }

    /// Issues which are not variants
    private TestCaseResult TestCaseLookup(String issueType, String url) {
        String[] urlElements = url.split("/");
        String testArea =
                urlElements[urlElements.length - 2].split("-")[0]; // .split strips off the -##

        int vtype = cweLookup(issueType, testArea);

        // Then get the filename containing the vuln. And if not in a test case, skip it.
        // Parse out test number from:
        // https://localhost:port/benchmark/testarea-##/BenchmarkTest02603
        int startOfTestCase = url.lastIndexOf("/") + 1;
        String testcase = url.substring(startOfTestCase, url.length());
        // if test case has extension (e.g., BenchmarkTestCase#####.html), strip it off.
        testcase = testcase.split("\\.")[0];
        // System.out.println("Candidate test case is: " + testcase);
        if (testcase.startsWith(BenchmarkScore.TESTCASENAME)) {
            int tn = testNumber(testcase);
            // if (tn == -1) System.out.println("Found vuln outside of test case of type: " +
            // issueType);

            // Add the vuln found in a test case to the results for this tool
            TestCaseResult tcr = new TestCaseResult();
            tcr.setNumber(tn);
            tcr.setCategory(issueType); // TODO: Is this right?
            tcr.setCWE(vtype);
            tcr.setEvidence(issueType);
            return tcr;
        }
        return null;
    }

    // Fetch Issues listed as variants, to cater to post 10.x release xml format
    private List<String> variantLookup(
            String issueType, String itemID, String startingUrl, List<Node> variants) {
        List<String> testCaseElementsFromVariants = new ArrayList<>();

        // System.out.println("Variant Lookup Item ID: " + itemID);

        for (Node variant : variants) {
            String variantUrlRefId = getNamedChild("url", variant).getTextContent().trim();
            String variantIssueType = getNamedChild("issue-type", variant).getTextContent().trim();
            // System.out.println("Variant Url Ref ID: " + variantUrlRefId);

            // Add the record only if the issue type matches for the relevant variants
            if (issueType.equals(variantIssueType) && itemID.equals(variantUrlRefId)) {
                Node variantNodes = getNamedChild("variant-group", variant);
                List<Node> variantNodeChildren = getNamedChildren("item", variantNodes);
                for (Node variantNodeChild : variantNodeChildren) {
                    String httpTraffic =
                            getNamedChild("test-http-traffic", variantNodeChild).getTextContent();
                    String[] variantUrl = httpTraffic.split(" ");

                    String benchMarkTestCase = variantUrl[1].trim();

                    if (benchMarkTestCase.contains("BenchmarkTest")) {
                        String[] urlElements = benchMarkTestCase.split("/");

                        String testAreaUrl =
                                startingUrl
                                        + urlElements[urlElements.length - 2]
                                        + "/"
                                        + urlElements[urlElements.length - 1];
                        String testArea = testAreaUrl.split("\\?")[0]; // .split strips off the -##

                        if (testArea.contains("BenchmarkTest"))
                            testCaseElementsFromVariants.add(testArea);
                    }
                }
            }
        }

        return testCaseElementsFromVariants;
    }

    private int cweLookup(String vtype, String testArea) {
        int cwe = cweLookup(vtype); // Do the standard CWE lookup

        // Then map some to other CWEs based on the test area being processed.
        if ("xpathi".equals(testArea) && cwe == 89) cwe = 643; // CWE for XPath injection
        if ("ldapi".equals(testArea) && cwe == 89) cwe = 90; // CWE for LDAP injection

        return cwe;
    }

    private int cweLookup(String vtype) {
        switch (vtype) {
            case "attDirectoryFound":
            case "attDirOptions":
            case "attFileUnix":
                return CweNumber.PATH_TRAVERSAL;

            case "attApplicationRemoteCodeExecutionAdns":
            case "attCodeInjectionInSystemCall":
            case "attCommandInjectionAdns":
            case "attCommandInjectionUnixTws":
            case "attFileParamPipe":
                return CweNumber.COMMAND_INJECTION;

            case "attCrossSiteScripting":
                return CweNumber.XSS;

            case "attBlindSqlInjectionStrings":
            case "attSqlInjectionChecks":
                return CweNumber.SQL_INJECTION;

            case "attLDAPInjection":
            case "attLDAPInjection2":
            case "attBlindLDAPInjection":
                return CweNumber.LDAP_INJECTION;

            case "SHA1CipherSuites":
                return CweNumber.WEAK_HASH_ALGO; // Better if set to 327?

            case "passParamGET":
                return CweNumber.UNPROTECTED_CREDENTIALS_TRANSPORT;

            case "attRespCookieNotSecureSSL":
                return CweNumber.INSECURE_COOKIE;

            case "attXPathInjection":
            case "attBlindXpathInjectionSingleQuote":
            case "attBlindXPathInjection":
                return CweNumber.XPATH_INJECTION;

                // These don't map to anything we care about
            case "attContentSecurityPolicyObjectSrc":
            case "attContentSecurityPolicyScriptSrc":
            case "attCachedSSL":
            case "attJSCookie":
                // case "attLinkInjection" : return 00;
            case "attUndefinedState":
            case "bodyParamsInQuery":
            case "ContentSecurityPolicy":
            case "ContentTypeOptions":
            case "GD_EmailAddress":
            case "GETParamOverSSL":
            case "GV_SQLErr":
                // case "HSTS" : return 00;

                // Microsoft MHTML XSS - Giving AppScan XSS 'credit' for this introduces ~2.4% False
                // Positives and no real ones so I (shivababuh) disabled it instead
            case "MHTMLXSS":
                // case "OpenSource" : return 00;  // Known vuln in open source lib.
                // case "phishingInFrames" : return 00;
            case "OldTLS":
            case "ShellShockCheck":
            case "SriSupport":
                // case "SSL_CertWithBadCN" : return 00;
                // case "XSSProtectionHeader" : return 00;
                return CweNumber.DONTCARE;

            default:
                System.out.println(
                        "WARNING: HCL AppScan Standard-Unrecognized finding type: " + vtype);
        }
        return 0;
    }
}
