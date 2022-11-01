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

import static org.owasp.benchmarkutils.score.TestSuiteResults.formatTime;

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

public class FortifyReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".fpr");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultZip) throws Exception {
        ResultFile resultFile = resultZip.extract("audit.fvdl");

        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new StringReader(resultFile.content()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("Fortify", true, TestSuiteResults.ToolType.SAST);

        // FIXME: Is there any way to get the time from Fortify itself?
        tr.setTime(resultZip.file());

        Node root = doc.getDocumentElement();

        if (isFortifyOnDemand(root)) {
            tr.setTool(tr.getToolName() + "-OnDemand");
        }

        // get engine build version and rulepack version
        tr.setToolVersion(fetchToolVersison(root));

        NodeList rootList = root.getChildNodes();
        List<Node> vulnList = getNamedNodes("Vulnerabilities", rootList);
        List<Node> vulns = getNamedChildren("Vulnerability", vulnList);

        for (Node flaw : vulns) {
            TestCaseResult tcr = parseFortifyVulnerability(flaw);
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    private String fetchToolVersison(Node root) {
        Node eData = getNamedChild("EngineData", root);
        String version = getNamedChild("EngineVersion", eData).getTextContent();
        Node rps = getNamedChild("RulePacks", eData);
        Node rp = getNamedChild("RulePack", rps);
        return version + "-rp" + getNamedChild("Version", rp).getTextContent();
    }

    /**
     * Try to figure out if this is Fortify On-Demand.
     *
     * <p>Note: I believe this only works for older versions of Fortify like 4.1. BenchmarkScore
     * contains a test for more recent versions of Fortify, like 4.3
     *
     * @param root
     * @return
     */
    private boolean isFortifyOnDemand(Node root) {
        return getNamedChild("SourceBasePath", getNamedChild("Build", root))
                .getTextContent()
                .contains("ronq");
    }

    public String parseTime(String filename) {
        try {
            // to make the same as normal filenames, strip off the '.fvdl' at the end of the
            // filename
            filename = filename.substring(0, filename.lastIndexOf('.') - 1);
            String time =
                    filename.substring(filename.lastIndexOf('-') + 1, filename.lastIndexOf('.'));
            int seconds = Integer.parseInt(time);
            return formatTime(seconds * 1000L);
        } catch (Exception e) {
            return "Time not specified";
        }
    }

    //        // Check to see if the results are regular Fortify or Fortify OnDemand results
    //        // To check, you have to look at the filtertemplate.xml file inside the .fpr archive
    //        // and see if that file contains: "Fortify-FOD-Template"
    //        outputFile = File.createTempFile(resultFile.filename() + "-filtertemplate", ".xml");
    //        source = fileSystem.getPath("filtertemplate.xml");
    //
    //        // In older versions of Fortify, like 4.1, the filtertemplate.xml file doesn't exist
    //        // So only check it if it exists
    //        try {
    //            Files.copy(source, outputFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
    //
    //            BufferedReader br = new BufferedReader(new FileReader(outputFile));
    //            try {
    //                StringBuilder sb = new StringBuilder();
    //                String line = br.readLine();
    //
    //                // Only read the first 3 lines and the answer is near the top of the file.
    //                int i = 1;
    //                while (line != null && i++ <= 3) {
    //                    sb.append(line);
    //                    line = br.readLine();
    //                }
    //                if (sb.indexOf("Fortify-FOD-") > -1) {
    //                    tr.setTool(tr.getToolName() + "-OnDemand");
    //                }
    //            } finally {
    //                br.close();
    //            }
    //        } catch (NoSuchFileException e) {
    //            // Do nothing if the filtertemplate.xml file doesn't exist in the .fpr archive
    //        } finally {
    //            outputFile.delete();
    //        }

    private TestCaseResult parseFortifyVulnerability(Node vuln) {
        TestCaseResult tcr = new TestCaseResult();

        Node ci = getNamedNode("ClassInfo", vuln.getChildNodes());
        Node type = getNamedNode("Type", ci.getChildNodes());
        String vulnType = type.getTextContent();
        tcr.setCategory(vulnType);

        // We grab this as sometimes we need to dig into this to verify the details of an issue
        Node ai = getNamedNode("AnalysisInfo", vuln.getChildNodes());
        Node un = getNamedNode("Unified", ai.getChildNodes());

        Node subtype = getNamedNode("Subtype", ci.getChildNodes());
        String vulnSubType = "";
        if (subtype != null) {
            vulnSubType = subtype.getTextContent();
        }
        tcr.setEvidence(vulnType + "::" + vulnSubType);

        tcr.setCWE(cweLookup(vulnType, vulnSubType, un));

        Node context = getNamedNode("Context", un.getChildNodes());
        Node function = getNamedNode("Function", context.getChildNodes());

        // The first block looks for class names for Java findings.
        String tc = getAttributeValue("enclosingClass", function);
        if (tc != null && tc.startsWith(BenchmarkScore.TESTCASENAME)) {
            tc = tc.substring(BenchmarkScore.TESTCASENAME.length());
            // This strips off inner classes from the test case file name I believe
            int dollar = tc.indexOf('$');
            if (dollar != -1) {
                tc = tc.substring(0, dollar);
            }
            int tn = Integer.parseInt(tc);
            tcr.setNumber(tn);
            return tcr;
        } else {
            /* if tc is null (from attribute enclosingClass), then this might be a NodeJS finding
               that looks like this:
                    <AnalysisInfo>
                      <Unified>
                        <Context>
                          <Function name="processRequest"/>
                          <FunctionDeclarationSourceLocation path="testcode/JulietJSTest00010.js" line="21" lineEnd="33" colStart="34" colEnd="0"/>
                        </Context>
            */
            if (tc == null) {
                Node functionDecl =
                        getNamedNode("FunctionDeclarationSourceLocation", context.getChildNodes());
                if (functionDecl != null) {
                    String path = getAttributeValue("path", functionDecl);
                    if (path != null) {
                        int i = path.indexOf(BenchmarkScore.TESTCASENAME);
                        if (i > 0) {
                            tc = path.substring(i);
                            tc =
                                    tc.substring(
                                            BenchmarkScore.TESTCASENAME.length(),
                                            tc.lastIndexOf('.'));
                            // This strips off inner classes from the test case file name I believe
                            int dollar = tc.indexOf('$');
                            if (dollar != -1) {
                                tc = tc.substring(0, dollar);
                            }
                            int tn = Integer.parseInt(tc);
                            tcr.setNumber(tn);
                            return tcr;
                        }
                    }
                }
            }
        }
        return null;
    }

    private CweNumber cweLookup(String vtype, String subtype, Node unifiedNode) {
        switch (vtype) {
            case "Access Control":
                return CweNumber.IMPROPER_ACCESS_CONTROL;

            case "Command Injection":
                return CweNumber.OS_COMMAND_INJECTION;

            case "Cookie Security":
                {
                    // Verify its the exact type we are looking for (e.g., not HttpOnly finding)
                    if ("Cookie not Sent Over SSL".equals(subtype)) {
                        return CweNumber.INSECURE_COOKIE;
                    } else {
                        return CweNumber.DONTCARE;
                    }
                }

            case "Cross-Site Request Forgery":
                return CweNumber.CSRF;

            case "Cross-Site Scripting":
                {
                    switch (subtype) {
                            // Not a type of XSS weakness we are testing for. Causes False Positives
                            // for Fortify.
                        case "Poor Validation":
                            return CweNumber.IMPROPER_NEUTRALIZATION_OF_ATTRIBUTES;
                    }
                    return CweNumber.XSS;
                }

            case "Dead Code":
                return CweNumber.DONTCARE;
            case "Denial of Service":
                return CweNumber.UNCONTROLLED_RESOURCE_CONSUMPTION;
            case "Dynamic Code Evaluation":
                return CweNumber.EVAL_INJECTION;
            case "Header Manipulation":
                return CweNumber.HTTP_RESPONSE_SPLITTING;
            case "Hidden Field":
                return CweNumber.EXTERNAL_CONTROL_OF_WEB_PARAM;
            case "Insecure Randomness":
                return CweNumber.WEAK_RANDOM;
            case "Key Management":
                return CweNumber.CATEGORY_KEY_MANAGEMENT_ERROR;
            case "LDAP Injection":
                return CweNumber.LDAP_INJECTION;
            case "Mass Assignment":
                return CweNumber.IMPROPER_CHECK_FOR_MODIFICATION;
            case "Missing Check against Null":
            case "Missing Check for Null Parameter":
                return CweNumber.NULL_POINTER_DEREFERENCE;
            case "Missing XML Validation":
                return CweNumber.MISSING_XML_VALIDATION;
            case "Null Dereference":
                return CweNumber.NULL_POINTER_DEREFERENCE;

                // Fortify reports weak randomness issues under Obsolete by ESAPI, rather than in
                // the Insecure Randomness category if it thinks you are using ESAPI. However, its
                // behavior isn't consistent. For Benchmark, we've seen it report it both ways. As
                // such, we are adding this other way to determine if Fortify is reporting weak
                // randomness. Given that Fortify reports many different types of issues under
                // this category, we actually look to see the name of the method they are flagging.
                // If its 'random()', then we count it as reported.
            case "Obsolete":
                {
                    if ("Deprecated by ESAPI".equals(subtype)) {
                        Node rd =
                                getNamedNode("ReplacementDefinitions", unifiedNode.getChildNodes());
                        Node def = getNamedNode("Def", "PrimaryCall.name", rd.getChildNodes());
                        String methodName = getAttributeValue("value", def);

                        // First check grants credit for flagging uses of: java.lang.Math.random()
                        if ("random()".equals(methodName)
                                ||

                                // Following grants credit for flagging use of any method that
                                // generates random #'s using the java.util.Random or
                                // java.security.SecureRandom classes. e.g., nextWHATEVER().
                                (methodName != null && methodName.startsWith("next"))) {
                            return CweNumber.WEAK_RANDOM;
                        }
                    }
                    return CweNumber.DONTCARE; // If neither of these, then don't care
                }

            case "Password Management":
                return CweNumber.DONTCARE;
            case "Path Manipulation":
                return CweNumber.PATH_TRAVERSAL;
            case "Poor Error Handling":
                return CweNumber.IMPROPER_CHECK_FOR_EXCEPTION_CONDITIONS;
            case "Poor Logging Practice":
                return CweNumber.MISSING_DEFAULT_CASE;
            case "Privacy Violation":
                return CweNumber.EXPOSURE_PRIVATE_TO_UNAUTHORIZED_USER;
            case "Resource Injection":
                return CweNumber.RESOURCE_INJECTION;
            case "SQL Injection":
                return CweNumber.SQL_INJECTION;
            case "System Information Leak":
                return CweNumber.ERROR_MESSAGE_WITH_SENSITIVE_INFO;
            case "Trust Boundary Violation":
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case "Unchecked Return Value":
                return CweNumber.UNCHECKED_RETURN_VALUE;
            case "Unreleased Resource":
                return CweNumber.UNRELEASED_RESOURCE;
            case "Unsafe Reflection":
                return CweNumber.UNSAFE_REFLECTION;
            case "Weak Cryptographic Hash":
                return CweNumber.WEAK_HASH_ALGO;
            case "Weak Encryption":
                {
                    switch (subtype) {
                            // These 2 are not types of Encryption weakness we are testing for.
                            // Cause False Positives for Fortify.
                        case "Missing Required Step":
                            return CweNumber.MISSING_CRYPTOGRAPHIC_STEP;
                        case "Inadequate RSA Padding":
                            return CweNumber.RSA_MISSING_PADDING;
                            // TODO: Assuming this Fortify rule is valid, we might need to fix
                            // Benchmark itself to eliminate unintended vulns.
                        case "Insecure Mode of Operation":
                            return CweNumber
                                    .DONTCARE; // Disable so it doesn't count against Fortify.
                    }
                    return CweNumber.WEAK_CRYPTO_ALGO;
                }

            case "XPath Injection":
                return CweNumber.XPATH_INJECTION;
            case "XQuery Injection":
                return CweNumber.XQUERY_INJECTION;
            case "XML Entity Expansion Injection":
                return CweNumber.XML_ENTITY_EXPANSION;
            case "XML External Entity Injection":
                return CweNumber.XXE;
                // Things we don't care about
            case "Build Misconfiguration":
            case "Code Correctness":
            case "Hardcoded Domain in HTML":
            case "J2EE Bad Practices":
            case "J2EE Misconfiguration":
            case "Object Model Violation":
            case "Poor Style":
            case "Portability Flaw":
            case "Race Condition":
            case "Redundant Null Check":
                return CweNumber.DONTCARE;

            default:
                System.out.println(
                        "Fortify parser encountered unknown vulnerability type: " + vtype);
        } // end switch

        return CweNumber.DONTCARE;
    }
}
