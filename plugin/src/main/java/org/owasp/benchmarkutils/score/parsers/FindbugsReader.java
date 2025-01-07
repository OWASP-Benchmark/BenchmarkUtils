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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

// This reader supports FindBugs/Spotbugs and FindSecBugs, since the later is simply a FindBugs
// plugin.
public class FindbugsReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("BugCollection");
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
                new TestSuiteResults("FindBugs", false, TestSuiteResults.ToolType.SAST);

        // If the filename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml), set the
        // compute time on the scorecard.
        tr.setTime(resultFile.file());

        // <BugCollection timestamp='1434663265000' analysisTimestamp='1434663273732' sequence='0'
        // release='' version='3.0.1>
        Node root = doc.getDocumentElement();
        String version = getAttributeValue("version", root);
        tr.setToolVersion(version);

        // If the findbugs version is greater than v3.0.x, it is actually SpotBugs
        if (!(version.startsWith("2") || version.startsWith("3.0"))) {
            tr.setTool("SpotBugs");
        }

        NodeList nl = root.getChildNodes();

        // Determine if FbContrib plugin was used during this analysis
        boolean hasFbContribPlugin = false;
        if (nl.item(0).getNodeName().equals("Project")) {
            // Loop through all Project nodes for Plugin nodes, as there can be more than one
            NodeList projectNodes = nl.item(0).getChildNodes();
            for (int i = 0; i < projectNodes.getLength(); i++) {
                Node n = projectNodes.item(i);
                if ("Plugin".equals(n.getNodeName())) {
                    String pluginName = getAttributeValue("id", n);
                    hasFbContribPlugin = "com.mebigfatguy.fbcontrib".equals(pluginName);
                    if (hasFbContribPlugin)
                        break; // If we have found a match, break out of for loop
                }
            }
        }

        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            if ("BugInstance".equals(n.getNodeName())) {
                TestCaseResult tcr = parseFindBugsBug(n);
                if (tcr != null) {
                    tr.put(tcr);
                }
            }
        }

        // change the name of the tool if the filename contains findsecbugs
        if (resultFile.filename().contains("findsecbugs")) {
            if (tr.getToolName().startsWith("Find")) {
                if (hasFbContribPlugin) tr.setTool("FBwFindSecBugs_wFb-contrib");
                else tr.setTool("FBwFindSecBugs");
            } else {
                if (hasFbContribPlugin) tr.setTool("SBwFindSecBugs_wFb-contrib");
                else tr.setTool("SBwFindSecBugs");
            }
        } // or if it contains fb-contrib
        else if (hasFbContribPlugin) {
            if (tr.getToolName().startsWith("Find")) {
                tr.setTool("FBwFb-contrib");
            } else {
                tr.setTool("SBwFb-contrib");
            }
        }

        return tr;
    }

    private TestCaseResult parseFindBugsBug(Node n) {
        NamedNodeMap attrs = n.getAttributes();
        String category = attrs.getNamedItem("category").getNodeValue();
        Node cl = getNamedNode("Class", n.getChildNodes());
        String classname = cl.getAttributes().getNamedItem("classname").getNodeValue();
        classname = classname.substring(classname.lastIndexOf('.') + 1);
        if (isTestCaseFile(classname)) {
            TestCaseResult tcr = new TestCaseResult();
            try {
                tcr.setActualResultTestID(classname);
                Node cweNode = attrs.getNamedItem("cweid");
                Node typeNode = attrs.getNamedItem("type");
                tcr.setCWE(figureCWE(tcr, cweNode, typeNode, category, classname));
                String type = attrs.getNamedItem("type").getNodeValue();
                tcr.setEvidence(type);

                return tcr;
            } catch (Exception e) {
                System.err.println(
                        "Error parsing node: " + n.toString() + " for classname: " + classname);
                e.printStackTrace();
                return null;
            }
        }
        return null;
    }

    private int figureCWE(
            TestCaseResult tcr, Node cweNode, Node typeNode, String category, String classname) {
        String cwe = null;
        if (cweNode != null) {
            cwe = cweNode.getNodeValue();
        }

        String type = null;
        if (typeNode != null) {
            type = typeNode.getNodeValue();
        }

        // Current FindBugs/SpotBugs/FindSecBugs all report a CWE, so we use those if provided.
        // All important bug patterns have their CWE ID associated in later versions (1.4.3+).
        if (cwe != null) {
            // The FI_NULLIFY_SUPER rule (Finalizer nullifies superclass finalizer) and
            // FI_MISSING_SUPER_CALL (Finalizer does not call superclass finalizer) in FindBugs <=
            // 7.5.0 erroneously reports these as CWE 586 but should be 568. This was reported to
            // SpotBugs as issue #3123, and should be fixed in SpotBugs 7.6.0+.
            if ("586".equals(cwe)
                    && ("FI_NULLIFY_SUPER".equals(type) || "FI_MISSING_SUPER_CALL".equals(type)))
                return 568; // finalize() Method without super.finalize()
            return Integer.parseInt(cwe);
        }

        // Fallback mapping for old versions of FindSecBugs plugin, before CWE id mappings were
        // provided in: findsecbugs-plugin/src/main/resources/metadata/findbugs.xml
        switch (type) {
                // Cookies
            case "INSECURE_COOKIE":
                return CweNumber.INSECURE_COOKIE;
            case "COOKIE_USAGE":
                return CweNumber.DONTCARE; // Not a vuln
            case "HTTPONLY_COOKIE":
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;

                // Injections
            case "SQL_INJECTION": // Yes, this is actually Hibernate Injection
            case "SQL_INJECTION_HIBERNATE":
                return CweNumber.HIBERNATE_INJECTION; // Hibernate Injection, child of SQL Injection

            case "SQL_INJECTION_JDBC":
            case "SQL_INJECTION_JDO":
            case "SQL_INJECTION_JPA":
            case "SQL_INJECTION_SPRING_JDBC":
                return CweNumber.SQL_INJECTION;

            case "LDAP_INJECTION":
                return CweNumber.LDAP_INJECTION;

            case "POTENTIAL_XML_INJECTION":
                return 91; // XML injection

            case "XPATH_INJECTION":
                return CweNumber.XPATH_INJECTION;

            case "COMMAND_INJECTION":
                return CweNumber.COMMAND_INJECTION;

            case "PREDICTABLE_RANDOM":
                return CweNumber.WEAK_RANDOM;

            case "PADDING_ORACLE":
                return 326; // Inadequate Encryption Strength

                // Weak encryption
            case "DES_USAGE": // weak encryption DES
                return CweNumber.WEAK_CRYPTO_ALGO;

            case "CIPHER_INTEGRITY": // weak encryption - cipher with no integrity
                return 353; // Missing support for Integrity Check

            case "STATIC_IV":
                return 329; // static initialization vector for crypto

                // Path traversal
            case "PATH_TRAVERSAL_IN":
            case "PATH_TRAVERSAL_OUT":
                return CweNumber.PATH_TRAVERSAL;

                // XSS
            case "XSS_JSP_PRINT":
            case "XSS_REQUEST_WRAPPER":
            case "XSS_SERVLET":
                return CweNumber.XSS;

                // XXE
            case "XXE_DOCUMENT":
            case "XXE_SAXPARSER":
            case "XXE_XMLREADER":
                return CweNumber.XXE;

                // Input sources
            case "SERVLET_CONTENT_TYPE": // Not a vuln
            case "SERVLET_PARAMETER": // Not a vuln
            case "SERVLET_HEADER": // Not a vuln
            case "SERVLET_HEADER_REFERER": // Use of Request Header -- spoofable
            case "SERVLET_QUERY_STRING": // Not a vuln
                return CweNumber.DONTCARE;

                // Technology detection
            case "SPRING_ENDPOINT": // Not a vuln
            case "JAXRS_ENDPOINT": // Not a vuln
                return CweNumber.DONTCARE;

                // Configuration
            case "OVERLY_PERMISSIVE_FILE_PERMISSION":
                return 732; // CWE-732: Incorrect Permission Assignment for Critical Resource

                // Other
            case "FORMAT_STRING_MANIPULATION":
                return 134; // Format String Manipulation
            case "HTTP_PARAMETER_POLLUTION":
                return 235; // HTTP Parameter Pollution (HPP)
            case "IMPROPER_UNICODE":
                return 176; // Improper Handling of Unicode Encoding
            case "WEAK_FILENAMEUTILS":
                return CweNumber.DONTCARE; // i.e., not filtering out Null bytes in file names

                // SPOTBUGS: Fallback mapping for old versions FindBugs/SpotBugs rules.
            case "DCN_NULLPOINTER_EXCEPTION": // Style: Caught NullPointer Exception
                return 395; // Use of NPE Catch to Detect NULL Pointer Dereference
            case "DP_DO_INSIDE_DO_PRIVILEGED": // Malicious Code: Do inside Do Privileged
                return 506; // Malicious Code
            case "HE_EQUALS_USE_HASHCODE": // Bad Practice:
            case "HE_HASHCODE_USE_OBJECT_EQUALS": // Bad Practice:
                return 581; // Just One of Equals and Hashcode Defined
            case "INT_VACUOUS_COMPARISON": // Style: Vacuous Comparison of Int Value
                return 570; // Expression is Always False
            case "NS_NON_SHORT_CIRCUIT": // Style: Non Short Circuit
                return 476; // Null Pointer Dereference
            case "OBL_UNSATISFIED_OBLIGATION": // Experimental: Unsatisfied Obligation
            case "ODR_OPEN_DATABASE_RESOURCE": // Bad Practice: Open Database resource
                return 772; // Missing Release of Resource after Effective Lifetime
            case "OS_OPEN_STREAM": // Bad Practice: Open Stream
                return 775; // Missing Release of File Descriptor or Handle after Effective Lifetime
            case "RANGE_ARRAY_INDEX": // Correctness: Range Array Index
                return 129; // Improper Validation of Array Index
            case "RR_NOT_CHECKED": // Bad Practice: Return value Not Checked
                return 252; // Unchecked return value
            case "SF_SWITCH_NO_DEFAULT": // Style: Switch no Default
                return 478; // Missing Default Case
            case "SA_LOCAL_SELF_ASSIGNMENT": // Style: Local Self Assignment
            case "UCF_USELESS_CONTROL_FLOW": // Style: Useless Control Flow
                return 398; // Code Quality
            case "UL_UNRELEASED_LOCK_EXCEPTION_PATH": // MT Correctness:
                return 833; // Deadlock
            case "UPM_UNCALLED_PRIVATE_METHOD": // Performance: Uncalled Private Method
                return 561; // Dead Code
            case "URF_UNREAD_FIELD": // Performance: Unread Field
            case "UUF_UNUSED_PUBLIC_OR_PROTECTED_FIELD": // Style:
                return 563; // Assignment to Variable without Use

                // Don't care about these:
            case "BC_UNCONFIRMED_CAST_OF_RETURN_VALUE": // Style:
            case "DB_DUPLICATE_BRANCHES": // Style:
            case "DM_CONVERT_CASE": // I18N:
            case "DM_DEFAULT_ENCODING": // I18N:
            case "DMI_INVOKING_TOSTRING_ON_ARRAY": // Correctness:
            case "INT_BAD_COMPARISON_WITH_INT_VALUE": // INT Correctness
            case "INT_BAD_COMPARISON_WITH_SIGNED_BYTE": // INT Correctness
            case "MSF_MUTABLE_SERVLET_FIELD": // MT Correctness:
            case "MTIA_SUSPECT_SERVLET_INSTANCE_FIELD": // Style:
            case "OBL_UNSATISFIED_OBLIGATION_EXCEPTION_EDGE": // Experimental:
            case "ODR_OPEN_DATABASE_RESOURCE_EXCEPTION_PATH": // Bad Practice:
            case "OS_OPEN_STREAM_EXCEPTION_PATH": // Bad Practice:
            case "PA_PUBLIC_PRIMITIVE_ATTRIBUTE": // Bad Practice:
            case "RI_REDUNDANT_INTERFACES": // Style:
            case "SE_NO_SERIALVERSIONID": // Bad Practice:
            case "SE_TRANSIENT_FIELD_NOT_RESTORED": // Bad Practice:
            case "SIC_INNER_SHOULD_BE_STATIC": // Performance:
            case "SIC_INNER_SHOULD_BE_STATIC_ANON": // Performance:
            case "SnVI_NO_SERIALVERSIONID": // Bad Practice:
            case "ST_WRITE_TO_STATIC_FROM_INSTANCE_METHOD": // Style:
            case "SWL_SLEEP_WITH_LOCK_HELD": // MT Correctness:
            case "UC_USELESS_CONDITION_TYPE": // Style
            case "UC_USELESS_OBJECT": // Style
            case "UC_USELESS_VOID_METHOD": // Style
            case "UWF_FIELD_NOT_INITIALIZED_IN_CONSTRUCTOR": // Style:
            case "UWF_NULL_FIELD": // Correctness: Field only ever set to null
                return CweNumber.DONTCARE;

                // These mappings are for fb-contrib
            case "AFBR_ABNORMAL_FINALLY_BLOCK_RETURN":
                return 705; // Incorrect Control Flow Scoping (parent of 584)

            case "AIOB_ARRAY_INDEX_OUT_OF_BOUNDS":
                return 129; // Improper Validation of Array Index

            case "IMC_IMMATURE_CLASS_PRINTSTACKTRACE":
                return 209; // Generation of Error Msg Containing Sensitive Info

            case "ISB_TOSTRING_APPENDING": // Correctness:
            case "LSC_LITERAL_STRING_COMPARISON": // Style:
            case "SNG_SUSPICIOUS_NULL_LOCAL_GUARD": // Correctness:
                return 476; // Null Pointer Dereference

            case "MDM_RANDOM_SEED":
                return 338; // Cryptographically Weak PRNG

            case "MDM_RUNTIME_EXIT_OR_HALT": // Correctness:
                return 382; // Use of System.exit()

            case "MDM_THREAD_YIELD": // MT Correctness:
                return 383; // Direct Use of Threads

            case "MDM_WAIT_WITHOUT_TIMEOUT":
                return 667; // Improper Locking

            case "NOS_NON_OWNED_SYNCHRONIZATION":
                return 833; // Deadlock

            case "RFI_SET_ACCESSIBLE":
                return 506; // Malicious Code

            case "UP_UNUSED_PARAMETER": // Style:
            case "WOC_WRITE_ONLY_COLLECTION_LOCAL": // Correctness:
                return 563; // Assignment to Variable without Use

            case "AI_ANNOTATION_ISSUES_NEEDS_NULLABLE": // Correctness:
            case "BED_BOGUS_EXCEPTION_DECLARATION": // Correct: declares except. it doesn't throw
            case "CC_CYCLOMATIC_COMPLEXITY":
            case "CLI_CONSTANT_LIST_INDEX": // Correctness:
            case "CSI_CHAR_SET_ISSUES_USE_STANDARD_CHARSET": // Style:
            case "CSI_CHAR_SET_ISSUES_USE_STANDARD_CHARSET_NAME": // Correctness:
            case "FCBL_FIELD_COULD_BE_LOCAL": // Correctness:
            case "IMC_IMMATURE_CLASS_BAD_SERIALVERSIONUID": // Correctness:
            case "IMC_IMMATURE_CLASS_NO_TOSTRING": // Style:
            case "IMC_IMMATURE_CLASS_UPPER_PACKAGE": // Style:
            case "IOI_USE_OF_FILE_STREAM_CONSTRUCTORS": // Performance:
            case "ISB_EMPTY_STRING_APPENDING": // Performance:
            case "LSYC_LOCAL_SYNCHRONIZED_COLLECTION": // Correctness:
            case "MDM_PROMISCUOUS_SERVERSOCKET": // Correctness:
            case "MRC_METHOD_RETURNS_CONSTANT": // Style:
            case "OCP_OVERLY_CONCRETE_PARAMETER": // Style:
            case "OPM_OVERLY_PERMISSIVE_METHOD": // Style:
            case "PCAIL_POSSIBLE_CONSTANT_ALLOCATION_IN_LOOP": // Performance:
            case "PRMC_POSSIBLY_REDUNDANT_METHOD_CALLS": // Performance:
            case "SEO_SUBOPTIMAL_EXPRESSION_ORDER": // Performance:
            case "SIL_SQL_IN_LOOP": // Performance:
            case "SPP_CONVERSION_OF_STRING_LITERAL": // Correctness:
            case "SPP_NON_USEFUL_TOSTRING": // Style:
            case "STT_STRING_PARSING_A_FIELD": // Style:
            case "SUA_SUSPICIOUS_UNINITIALIZED_ARRAY": // Correctness:
            case "UNNC_UNNECESSARY_NEW_NULL_CHECK": // Correctness:
            case "USBR_UNNECESSARY_STORE_BEFORE_RETURN": // Style:
                // Use Try w/Resources doesn't necessarily mean: CWE 772: Missing Release of
                // Resource after Effective Lifetime
            case "UTWR_USE_TRY_WITH_RESOURCES": // Style:
            case "UVA_USE_VAR_ARGS": // Style:
            case "WEM_WEAK_EXCEPTION_MESSAGING": // Style:
                return CweNumber.DONTCARE;

            default:
                System.err.println(
                        "Findbugs unknown vuln type: "
                                + type
                                + " in category: "
                                + category
                                + " in class: "
                                + classname);
        }

        return CweNumber.UNKNOWN;
    }
}
