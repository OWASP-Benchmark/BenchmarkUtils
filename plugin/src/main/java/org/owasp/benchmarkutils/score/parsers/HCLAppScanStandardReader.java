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

import static java.lang.Integer.parseInt;

import java.util.ArrayList;
import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

/**
 * This is the new HCL AppScan DAST reader, where they generate ".xml" files. HCL calls this AppScan
 * Standard. The 'old' reader is AppScanDynamicReader, which supports the previous .xml format from
 * IBM.
 */
public class HCLAppScanStandardReader extends Reader {

    private final List<String> ignoreList = new ArrayList<>();

    public HCLAppScanStandardReader() {
        ignoreList.add("attContentSecurityPolicyObjectSrc");
        ignoreList.add("attContentSecurityPolicyScriptSrc");
        ignoreList.add("attCachedSSL");
        ignoreList.add("attJSCookie");
        ignoreList.add("attLinkInjection");
        ignoreList.add("attUndefinedState");
        ignoreList.add("bodyParamsInQuery");
        ignoreList.add("ContentSecurityPolicy");
        ignoreList.add("ContentTypeOptions");
        ignoreList.add("GD_EmailAddress");
        ignoreList.add("GETParamOverSSL");
        ignoreList.add("GV_SQLErr");
        ignoreList.add("HSTS");
        ignoreList.add("MHTMLXSS");
        ignoreList.add("OpenSource");
        ignoreList.add("phishingInFrames");
        ignoreList.add("OldTLS");
        ignoreList.add("ShellShockCheck");
        ignoreList.add("SriSupport");
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("xml-report")
                && "AppScan Report".equals(getAttributeValue("name", resultFile.xmlRootNode()))
                && "DAST".equals(getAttributeValue("technology", resultFile.xmlRootNode()));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        Node root = resultFile.xml().getDocumentElement();

        TestSuiteResults tr =
                new TestSuiteResults("HCL AppScan Standard", true, TestSuiteResults.ToolType.DAST);

        setTime(root, tr);
        setVersion(root, tr);

        List<Node> variants = getNamedChildren("item", getNamedChild("issue-group", root));

        for (Node variant : variants) {
            int xmlCwe = parseInt(getNamedChild("cwe", variant).getTextContent());
            String variantIssueType = getNamedChild("issue-type", variant).getTextContent().trim();

            getNamedChildren("item", getNamedChild("variant-group", variant)).stream()
                    .map(node -> extractFilenameWithoutEnding(extractUrlFrom(node)))
                    .filter(filename -> filename.startsWith(BenchmarkScore.TESTCASENAME))
                    .forEach(
                            filename -> {
                                TestCaseResult tcr = new TestCaseResult();

                                tcr.setNumber(testNumber(filename));
                                tcr.setCategory(variantIssueType); // TODO: Is this right?
                                tcr.setCWE(cweLookup(variantIssueType, xmlCwe));
                                tcr.setEvidence(variantIssueType);

                                tr.put(tcr);
                            });
        }

        return tr;
    }

    private void setTime(Node root, TestSuiteResults tr) {
        tr.setTime(
                getNamedChild("scan-Duration", getNamedChild("scan-summary", root))
                        .getTextContent());
    }

    private static String extractUrlFrom(Node variantNodeChild) {
        String[] variantUrl =
                getNamedChild("test-http-traffic", variantNodeChild).getTextContent().split(" ");

        return variantUrl[1].trim();
    }

    /*
     * Version is usually like 9.3.0 but sometimes like 9.3.0 iFix005. We trim off the part after the space char.
     */
    private static void setVersion(Node root, TestSuiteResults tr) {
        Node version = getNamedChild("product-version", getNamedChild("scan-information", root));

        if (version != null) {
            tr.setToolVersion(version.getTextContent().split(" ")[0]);
        }
    }

    private int cweLookup(String vtype, int xmlCwe) {
        switch (vtype) {
            case "attXPathInjection":
            case "attBlindXpathInjectionSingleQuote":
            case "attBlindXPathInjection":
                return CweNumber.XPATH_INJECTION;
        }

        if (ignoreList.contains(vtype)) {
            return CweNumber.DONTCARE;
        }

        return xmlCwe;
    }
}
