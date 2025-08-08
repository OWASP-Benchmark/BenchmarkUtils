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

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
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
        InputStream stream = resultZip.extract("audit.fvdl");

        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new InputStreamReader(stream));
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

    private static String fetchToolVersison(Node root) {
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
    private static boolean isFortifyOnDemand(Node root) {
        return getNamedChild("SourceBasePath", getNamedChild("Build", root))
                .getTextContent()
                .contains("ronq");
    }

    public static String parseTime(String filename) {
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

    private static TestCaseResult parseFortifyVulnerability(Node vuln) {
        TestCaseResult tcr = new TestCaseResult();

        // Get the vulnerability type and subtype, if specified
        Node ci = getNamedNode("ClassInfo", vuln.getChildNodes());
        Node type = getNamedNode("Type", ci.getChildNodes());
        String vulnType = type.getTextContent();

        Node subtype = getNamedNode("Subtype", ci.getChildNodes());
        String vulnSubType = "";
        if (subtype != null) {
            vulnSubType = subtype.getTextContent();
        }
        tcr.setEvidence(vulnType + "::" + vulnSubType);

        // We grab this as sometimes we need to dig into this to verify the details of an issue
        Node ai = getNamedNode("AnalysisInfo", vuln.getChildNodes());
        Node un = getNamedNode("Unified", ai.getChildNodes());

        Node context = getNamedNode("Context", un.getChildNodes());
        Node function = getNamedNode("Function", context.getChildNodes());

        // The first block looks for class names for Java findings.
        String tc = getAttributeValue("enclosingClass", function);

        tcr.setCWE(cweLookup(vulnType, vulnSubType, un, tc));

        if (tc != null) {
            // Strip off inner class name from the test case file name if present
            int dollar = tc.indexOf('$');
            if (dollar != -1) {
                tc = tc.substring(0, dollar);
            }
            if (isTestCaseFile(tc)) {
                tcr.setActualResultTestID(tc);
                return tcr;
            } /* commented out - DEBUG only - else
                         System.out.println(
                                 "DEBUG: Fortify parser found vulnerability of type: "
                                         + vulnType
                                         + " with subType: "
                                         + vulnSubType
                                         + " but its enclosingClass value is: "
                                         + tc
                                         + " so its being discarded");
              */
        } else {
            /* if tc is null (from attribute enclosingClass), then this might be a NodeJS finding, or C/C++
               that looks like this:
                    <AnalysisInfo>
                      <Unified>
                        <Context>
                          <Function name="processRequest"/>
                          <FunctionDeclarationSourceLocation path="testcode/TestSuiteTest00010.js" line="21" lineEnd="33" colStart="34" colEnd="0"/>
                        </Context>
            */
            Node functionDecl =
                    getNamedNode("FunctionDeclarationSourceLocation", context.getChildNodes());
            if (functionDecl != null) {
                String path = getAttributeValue("path", functionDecl);
                if (path != null) {
                    if (isTestCaseFile(path)) {
                        path = extractFilenameWithoutEnding(path);
                        tcr.setActualResultTestID(path);
                        return tcr;
                    } /* Comment out debug code
                      else
                        System.out.println(
                                "DEBUG: Fortify parser found vulnerability of type: "
                                        + vulnType
                                        + " with subType: "
                                        + vulnSubType
                                        + " but its FunctionDeclarationSourceLocation value is: "
                                        + path
                                        + " so its being discarded");
                      */
                    // DRW TODO: Remove this OLD / commented out code
                    /* The following is the old code being replaced:
                    int i = path.indexOf(BenchmarkScore.TESTCASENAME); // todo: Replace with StartsWith Match for Juliet style test cases.
                    if (i >= 0) {
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
                        tcr.setTestID(Integer.parseInt(tc));
                        return tcr;
                    }
                    old code commented out */
                }
            } else if (!"Password in Comment".equals(vulnSubType))
                System.out.println(
                        "WARNING: Fortify parser found vulnerability of type: "
                                + vulnType
                                + " with subType: "
                                + vulnSubType
                                + " but it has no FunctionDeclarationSourceLocation Node, so can't determine where the vuln was found.");
        }
        return null;
    }

    public static int cweLookup(String vtype, String subtype, Node unifiedNode, String classname) {

        switch (vtype) {
            case "Access Control":
            case "Access Specifier Manipulation":
                return CweNumber.IMPROPER_ACCESS_CONTROL;

            case "Buffer Overflow":
                {
                    switch (subtype) {
                            // The following are all mapped to CWE-119 since Fortify is
                            // specifically saying this is a buffer overflow
                        case "":
                        case "Format String": // NOT specifying CWE 134: Use of
                            // Externally-Controlled Format String
                        case "Off-by-One": // NOT specifying CWE 193: Off-by-one error
                        case "Signed Comparison": // NOT specifying CWE-839: Numeric Range
                            // Comparison w/out minimum check
                            return 119; // Improper Restriction of Operations within Bounds of
                            // Memory Buffer

                        default:
                            System.out.println(
                                    "Fortify parser found vulnerability type: 'Buffer Overflow', with unmapped subtype: '"
                                            + subtype
                                            + "' in class: "
                                            + classname);
                            return 119; // Improper Restriction of Operations within Bounds of
                            // Memory Buffer
                    }
                }

            case "Code Correctness":
                {
                    switch (subtype) {
                        case "Call to sleep() in Lock":
                            return 833; // Deadlock
                        case "Call to Thread.run()":
                            return 572; // Call to Thread run() instead of start()
                        case "Erroneous finalize() Method":
                            return 568; // finalize() Method without super.finalize()
                        case "Erroneous String Compare":
                            return 597; // Use of Wrong Operator in String Comparison

                        case "Byte Array to String Conversion":
                        case "Constructor Invokes Overridable Function":
                        case "Multiple Stream Commits":
                        case "String Comparison of Float":
                        case "ToString on Array":
                            return CweNumber.DONTCARE;

                        default:
                            if (classname != null)
                                System.out.println(
                                        "Fortify parser found vulnerability type: 'Code Correctness', with unmapped subtype: '"
                                                + subtype
                                                + "' in class: "
                                                + classname);
                    }
                    return CweNumber.UNMAPPED;
                }

            case "Command Injection":
                return CweNumber.COMMAND_INJECTION;

            case "Connection String Parameter Pollution":
                return 15; // External Control of System or Configuration Setting

            case "Cookie Security":
                {
                    switch (subtype) {
                        case "Cookie not Sent Over SSL":
                            return CweNumber.INSECURE_COOKIE;
                        case "HTTPOnly not Set":
                            return CweNumber.COOKIE_WITHOUT_HTTPONLY;
                        case "Persistent Cookie":
                            return 539; // Use of Persistent Cookie Containing Sensitive Info
                        default:
                            if (classname != null)
                                System.out.println(
                                        "Fortify parser found vulnerability type: 'Cookie Security', with unmapped subtype: '"
                                                + subtype
                                                + "' in class: "
                                                + classname);
                    }
                    return CweNumber.UNMAPPED;
                }

            case "Cross-Site Request Forgery":
                return CweNumber.CSRF;

            case "Cross-Site Scripting":
                switch (subtype) {
                    case "Poor Validation":
                        return 20; // CWE-20 Improper Input Validation
                    default:
                        return CweNumber.XSS;
                }
            case "Dangerous Function": // CWE-1177 Use of Prohibited Code is parent of both:
                return 1177; // CWE-242 Use of Inherently Dangerous Function and CWE-676 Use of
                // Potentially Dangerous Function
            case "Dead Code":
                return 561; // Dead Code
            case "Denial of Service":
                return 400; // Uncontrolled Resource Consumption
            case "Dynamic Code Evaluation":
                return 95; // Improper Neutralization of Directives in Dynamically Evaluated Code
                // (Eval Injection)
            case "Header Manipulation":
                return 113; // HTTP Response Splitting
            case "Hidden Field":
                return 472; // External Control of Assumed-Immutable Web Parameter
            case "Insecure Randomness":
                {
                    switch (subtype) {
                        case "":
                            return CweNumber.WEAK_RANDOM;
                        case "Hardcoded Seed":
                            return 336; // Same Seed in PRNG
                        default:
                            if (classname != null)
                                System.out.println(
                                        "Fortify parser found vulnerability type: 'Insecure Randomness', with unmapped subtype: '"
                                                + subtype
                                                + "' in class: "
                                                + classname);
                    }
                    return CweNumber.WEAK_RANDOM;
                }

            case "Insecure Transport":
                return 319; // Cleartext Transmission of Sensitive Info

                // Deprecated rule set last updated in 2017
            case "Insider Threat":
                {
                    switch (subtype) {
                        case "Email Spying":
                        case "Hardcoded External Command":
                        case "Network Communication":
                        case "Network Port Listening":
                        case "Time Bomb":
                            return 506; // Embedded Malicious Code

                        case "Redundant Condition":
                            return 481; // Assigning instead of Comparing

                        case "Reflection Abuse":
                            return 470; // Unsafe Reflection

                        case "Suspicious String": // Don't know what this means
                            return CweNumber.UNMAPPED;

                        default:
                            if (classname != null)
                                System.out.println(
                                        "Fortify parser found vulnerability type: 'Insider Threat', with unmapped subtype: '"
                                                + subtype
                                                + "' in class: "
                                                + classname);
                    }
                    return CweNumber.UNMAPPED;
                }

            case "J2EE Bad Practices":
                {
                    switch (subtype) {
                        case "getConnection()":
                            return 319; // Cleartest Transmission of Sensitive Info
                        case "Insufficient Session Expiration":
                            return 613; // Insufficient Session Expiration
                        case "JVM Termination":
                            return CweNumber.SYSTEM_EXIT;
                        case "Leftover Debug Code":
                            return 489; // Active Debug Code
                        case "Non-Serializable Object Stored in Session":
                            return 579; // Non-serializable Object Stored in Session
                        case "Sockets":
                            return CweNumber.DONTCARE;
                        case "Threads":
                            return 383; // Direct Use of Threads
                        default:
                            if (classname != null)
                                System.out.println(
                                        "Fortify parser found vulnerability type: 'J2EE Bad Practices', with unmapped subtype: '"
                                                + subtype
                                                + "' in class: "
                                                + classname);
                    }
                    return CweNumber.UNMAPPED;
                }

            case "Key Management":
                return 320; // Key Management Errors

            case "LDAP Injection":
                return CweNumber.LDAP_INJECTION;
            case "Log Forging":
                return 117; // Improper Output Neutralization for Logs

            case "Mass Assignment":
                return 915; // Improper Controlled Modif of Dynamically-Determined Obj Attributes

            case "Missing Check against Null":
            case "Missing Check for Null Parameter":
            case "Null Dereference":
            case "Redundant Null Check":
                return 476; // Null Pointer Dereference

            case "Missing XML Validation":
                return 112; // Missing XML Validation

            case "Object Model Violation":
                return 581; // Object Model Violation: Just One of Equals and Hashcode Defined

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
                    return 477; // Use of Obsolete Function
                }

            case "Often Misused":
                return 510; // Trapdoor
            case "Open Redirect":
                return CweNumber.OPEN_REDIRECT;
            case "Password Management":
                {
                    switch (subtype) {
                        case "Empty Password":
                            return 256; // Plaintext Storage of a Password
                        case "Hardcoded Password":
                            return 259; // Use of Hard-coded Password
                        case "Null Password":
                            return 1391; // Weak Credentials
                        case "": // Don't know what blank sub type means so can't map it
                        case "Password in Comment":
                            return CweNumber.DONTCARE;
                        case "Weak Cryptography":
                            return 522; // Insufficiently Protected Credentials
                        default:
                            if (classname != null)
                                System.out.println(
                                        "Fortify parser found vulnerability type: 'Password Management', with unmapped subtype: '"
                                                + subtype
                                                + "' in class: "
                                                + classname);
                    }
                    return CweNumber.UNMAPPED;
                }
            case "Path Manipulation":
                return CweNumber.PATH_TRAVERSAL;
            case "Process Control":
                return 114; // Process Control
            case "Poor Error Handling":
                {
                    switch (subtype) {
                        case "Empty Catch Block":
                            return 390; // Detection of Error Condition Without Action

                        case "Overly Broad Catch":
                        case "Overly Broad Throws":
                        case "Throw Inside Finally":
                            return 703; // Improper Check or Handling of Exceptional Conditions

                        case "Program Catches NullPointerException":
                            return 395; // Use of NullPointerException Catch to Detect NPE

                        case "Return Inside Finally":
                            return 584; // Return Inside Finally Block

                        default:
                            System.out.println(
                                    "Fortify parser found vulnerability type: 'Poor Error Handling', with unmapped subtype: '"
                                            + subtype
                                            + "' in class: "
                                            + classname);
                    }
                    return 703; // Improper Check or Handling of Exceptional Conditions
                }

            case "Poor Style":
                {
                    switch (subtype) {
                        case "Non-final Public Static Field":
                            return 500; // Public Static Field Not Marked Final
                        case "Value Never Read":
                            return 563; // Assignment to Variable without Use
                        case "Empty Synchronized Block":
                            return 585; // Empty Synchronized Block
                        case "Explicit Call to finalize()":
                            return 586; // Explicit Call to finalize()
                        case "Redundant Initialization":
                            return CweNumber.DONTCARE;
                        default:
                            System.out.println(
                                    "Fortify parser found vulnerability type: 'Poor Style', with unmapped subtype: '"
                                            + subtype
                                            + "' in class: "
                                            + classname);
                    }
                    return CweNumber.DONTCARE;
                }

            case "Privacy Violation":
                return 359; // Exposure of Private Personal Info
            case "Race Condition":
                return 362;
            case "Resource Injection":
                return 99; // Resource Injection

            case "Setting Manipulation":
                return 15; // External Control of System or Config Setting
            case "SQL Injection":
                return CweNumber.SQL_INJECTION;
            case "String Termination Error":
                return 170; // Improper Null Termination
            case "System Information Leak":
                return 209; // Generation of Error Msg Containing Sensitive Info
            case "Trust Boundary Violation":
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case "Unchecked Return Value":
                return 252; // Unchecked Return value
            case "Unreleased Resource":
                return 404; // Improper Resource Shutdown or Release
            case "Unsafe JNI":
                return 111; // Direct Use of Unsafe JNI
            case "Unsafe Reflection":
                return 470; // Unsafe Reflection

            case "Weak Cryptographic Hash":
                {
                    switch (subtype) {
                        case "":
                        case "User-Controlled Algorithm":
                            return CweNumber.WEAK_HASH_ALGO;
                        case "Missing Required Step":
                            return 325; // Missing Required Step
                        default:
                            System.out.println(
                                    "Fortify parser found vulnerability type: 'Weak Cryptographic Hash', with unmapped subtype: '"
                                            + subtype
                                            + "' in class: "
                                            + classname);
                    }
                    return CweNumber.WEAK_HASH_ALGO;
                }

            case "Weak Encryption":
                {
                    switch (subtype) {
                        case "": // No subtype, so report as weak encryption
                            return CweNumber.WEAK_CRYPTO_ALGO;

                            // These 2 are not types of Encryption weakness we are testing for.
                            // Cause False Positives for Fortify.
                        case "Missing Required Step":
                            return 325; // Missing Required Step
                        case "Inadequate RSA Padding":
                            return 780; // Use of RSA Algo w/out OAEP

                        case "Insecure Initialization Vector":
                        case "Insufficient Key Size":
                            return 1204; // Generation of Weak Initialization Vector (IV)

                            // TODO: Assuming this Fortify rule is valid, we might need to fix
                            // Benchmark itself to eliminate unintended vulns.
                        case "Insecure Mode of Operation":
                            return CweNumber
                                    .DONTCARE; // Disable so it doesn't count against Fortify.
                        default:
                            System.out.println(
                                    "Fortify parser found vulnerability type: 'Weak Encryption', with unmapped subtype: '"
                                            + subtype
                                            + "' in class: "
                                            + classname);
                    }
                    return CweNumber.WEAK_CRYPTO_ALGO;
                }

            case "XPath Injection":
                return CweNumber.XPATH_INJECTION;

            case "XQuery Injection":
                return CweNumber.XQUERY_INJECTION;

            case "XML Entity Expansion Injection":
                return CweNumber.XEE;

            case "XML External Entity Injection":
                return CweNumber.XXE;

                // Things we don't care about
            case "Build Misconfiguration":
            case "Hardcoded Domain in HTML":
            case "J2EE Misconfiguration":
            case "Poor Logging Practice":
            case "Portability Flaw":
            case "Registry Manipulation":
                return CweNumber.DONTCARE;

            default:
                System.out.println(
                        "Fortify parser found unknown vulnerability type: "
                                + vtype
                                + ", with subtype: '"
                                + subtype
                                + "' in class: "
                                + classname);
        } // end switch

        return CweNumber.UNMAPPED;
    }
}
