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
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

// This reader supports both FindBugs and FindSecBugs, since the later is simply a FindBugs plugin.
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
        for (int i = 0; i < nl.getLength(); i++) {
            Node n = nl.item(i);
            if (n.getNodeName().equals("BugInstance")) {
                TestCaseResult tcr = parseFindBugsBug(n);
                if (tcr != null) {
                    tr.put(tcr);
                }
            }
        }

        // change the name of the tool if the filename contains findsecbugs
        if (resultFile.filename().contains("findsecbugs")) {
            if (tr.getToolName().startsWith("Find")) {
                tr.setTool("FBwFindSecBugs");
            } else {
                tr.setTool("SBwFindSecBugs");
            }
        }

        return tr;
    }

    private TestCaseResult parseFindBugsBug(Node n) {
        NamedNodeMap attrs = n.getAttributes();
        if (attrs.getNamedItem("category").getNodeValue().equals("SECURITY")) {
            Node cl = getNamedNode("Class", n.getChildNodes());
            String classname = cl.getAttributes().getNamedItem("classname").getNodeValue();
            classname = classname.substring(classname.lastIndexOf('.') + 1);
            if (classname.startsWith(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();
                try {
                    tcr.setNumber(testNumber(classname));
                    Node cwenode = attrs.getNamedItem("cweid");
                    Node catnode = attrs.getNamedItem("abbrev");
                    tcr.setCWE(figureCWE(tcr, cwenode, catnode));

                    String type = attrs.getNamedItem("type").getNodeValue();
                    tcr.setCategory(type);

                    return tcr;
                } catch (Exception e) {
                    // System.out.println("Error parsing node: " + n.toString() + " for classname: "
                    // + classname);
                    return null; // If we can't parse the test #, its not in a real test case file.
                    // e.g., BenchmarkTesting.java
                }
            }
        }
        return null;
    }

    private CweNumber figureCWE(TestCaseResult tcr, Node cwenode, Node catnode) {
        String cwe = null;
        if (cwenode != null) {
            cwe = cwenode.getNodeValue();
        }

        String cat = null;
        if (catnode != null) {
            cat = catnode.getNodeValue();
        }
        tcr.setEvidence("FB:" + cwe + "::" + cat);

        if (cwe != null) {
            // FIX path traversal CWEs
            if (cwe.equals("23") || cwe.equals("36")) {
                cwe = "22";
            }
            // FSB identify DES/DESede as CWE-326 (Inadequate Encryption Strength) while Benchmark
            // marked it as CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
            else if (cwe.equals("326")) {
                cwe = "327";
            }
            return CweNumber.lookup(cwe);
        }

        // This is a fallback mapping for unsupported/old versions of the Find Security Bugs plugin
        // as defined in: findsecbugs-plugin/src/main/resources/metadata/findbugs.xml
        // All important bug patterns have their CWE ID associated in later versions (1.4.3+).
        switch (cat) {
                // Cookies
            case "SECIC":
                return CweNumber.INSECURE_COOKIE;
            case "SECCU":
                return CweNumber.DONTCARE;
            case "SECHOC":
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;

                // Injections
            case "SECSQLIHIB":
                return CweNumber.HIBERNATE_INJECTION;
            case "SECSQLIJDO":
            case "SECSQLIJPA":
            case "SECSQLISPRJDBC":
            case "SECSQLIJDBC":
                return CweNumber.SQL_INJECTION;

                // LDAP injection
            case "SECLDAPI":
                return CweNumber.LDAP_INJECTION;

                // XPath injection
            case "SECXPI":
                return CweNumber.XPATH_INJECTION;

                // Command injection
            case "SECCI":
                return CweNumber.OS_COMMAND_INJECTION;

                // Weak random
            case "SECPR":
                return CweNumber.WEAK_RANDOM;

                // Weak encryption
            case "SECDU": // weak encryption DES
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "CIPINT": // weak encryption - cipher with no integrity
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "PADORA": // padding oracle -- FIXME: probably wrong
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "STAIV":
                return CweNumber.STATIC_CRYPTO_INIT;

                // Weak hash
            case "SECWMD":
                return CweNumber.WEAK_HASH_ALGO;

                // Path traversal
            case "SECPTO":
            case "SECPTI":
                return CweNumber.PATH_TRAVERSAL;

                // XSS
            case "SECXRW":
            case "SECXSS1":
            case "SECXSS2":
                return CweNumber.XSS;

                // XXE
            case "SECXXEDOC":
            case "SECXXEREAD":
            case "SECXXESAX":
                return CweNumber.XXE;

                // Input sources
            case "SECSP": // servlet parameter - not a vuln
                return CweNumber.DONTCARE;
            case "SECSH": // servlet header - not a vuln
                return CweNumber.DONTCARE;
            case "SECSHR": // Use of Request Header -- spoofable
                return CweNumber.DONTCARE;
            case "SECSSQ": // servlet query - not a vuln
                return CweNumber.DONTCARE;

                // Technology detection
            case "SECSC": // found Spring endpoint - not a vuln
                return CweNumber.DONTCARE;
            case "SECJRS": // JAX-RS Endpoint
                return CweNumber.DONTCARE;

                // Configuration
            case "SECOPFP": // Overly Permissive File Permissions
                return CweNumber.DONTCARE;

                // Other
            case "SECHPP":
                return CweNumber.IMPROPER_HANDLING_OF_PARAMETERS;
            case "SECUNI": // Improper Unicode
                return CweNumber.DONTCARE;
            case "SECWF": // Weak Filename Utils - i.e., not filtering out Null bytes in file names
                return CweNumber.DONTCARE;

            default:
                System.out.println("Unknown vuln category for FindBugs: " + cat);
        }

        return CweNumber.DONTCARE;
    }
}
