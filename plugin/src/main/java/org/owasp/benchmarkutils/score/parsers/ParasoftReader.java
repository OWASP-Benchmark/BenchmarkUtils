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
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class ParasoftReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && (resultFile.line(1).startsWith("<ResultsSession")
                        || resultFile.line(0).contains("<ResultsSession"));
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

        // <ResultsSession time="06/03/15 10:10:09" toolDispName="Jtest" toolVer="9.5.13.20140908>
        String toolName = getAttributeValue("toolDispName", root);
        if (toolName == null) toolName = "Parasoft Jtest";
        else toolName = "Parasoft " + toolName;
        // C/C++ test is the name of one of their tools and the / breaks file names, so replacing it
        // with _
        toolName = toolName.replace('/', '_');
        String version = getAttributeValue("toolVer", root);

        // This parser supports multiple Parasoft language specific SAST tools, so we have to get
        // the name of the tool from the results file itself (e.g., Jtest, dotTEST, etc.)
        TestSuiteResults tr = new TestSuiteResults(toolName, true, TestSuiteResults.ToolType.SAST);

        tr.setToolVersion(version);

        NodeList rootList = root.getChildNodes();
        List<Node> stds = getNamedNodes("CodingStandards", rootList);
        Node std = stds.get(0);
        String time = getAttributeValue("time", std);
        tr.setTime(time);

        // Have to grab all the Rules so we can look up the origId name of any rules that have been
        // renamed to be CWE.NN.FOO
        Node rulesNode = getNamedChild("Rules", std); // Grab the 1 Rules node
        Node rulesListNode = getNamedChild("RulesList", rulesNode); // Grab the 1 RulesList node
        List<Node> rulesList = getNamedChildren("Rule", rulesListNode);

        List<Node> viols = getNamedChildren("StdViols", std);

        List<Node> stdList = getNamedChildren("StdViol", viols);

        List<Node> flowList = getNamedChildren("FlowViol", viols);

        for (Node flaw : stdList) {
            TestCaseResult tcr = this.parseStdViol(flaw, rulesList);
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        for (Node flaw : flowList) {
            TestCaseResult tcr = this.parseFlowViol(flaw, rulesList);
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private TestCaseResult parseStdViol(Node flaw, List<Node> rules) {
        // <StdViol sev="2" ln="49" cat="SECURITY.IBA" hash="395273668" tool="jtest" locType="sr"
        // msg="'getName()' is a dangerous data-returning method and should be encapsulated by a
        // validation" lang="java" rule="SECURITY.IBA.VPPD" config="1" auth="kupsch" locOffs="1749"
        // locLen="7" locFile="/temp/java/org/owasp/benchmark/testcode/BenchmarkTest00003.java" />

        TestCaseResult tcr = new TestCaseResult();
        String ruleId = getAttributeValue("rule", flaw);
        if (ruleId == null) {
            System.err.println("WARNING: No 'rule' attribute found for Violation node: " + flaw);
        } else {
            // Look up the origId, if any, for the rule specified where the rule's id = ruleId
            Node rule = getNodeWithMatchingKeyAndValue("id", ruleId, rules);
            if (rule == null) {
                System.err.println("WARNING: no matching rule found for ruleId: " + ruleId);
            }

            String origId = getAttributeValue("origId", rule);

            int cweVal = cweLookup(ruleId, origId);
            tcr.setCWE(cweVal);

            tcr.setConfidence(Integer.parseInt(getAttributeValue("sev", flaw)));
            tcr.setEvidence(
                    getAttributeValue("rule", flaw) + "::" + getAttributeValue("msg", flaw));

            String testcase = getAttributeValue("locFile", flaw);
            testcase = testcase.substring(testcase.lastIndexOf('/') + 1);
            if (isTestCaseFile(testcase)) {
                tcr.setActualResultTestID(testcase);
                return tcr;
            }
        }
        return null;
    }

    private TestCaseResult parseFlowViol(Node flaw, List<Node> rules) {
        // <FlowViol sev="1" ln="64" hash="-1497144802" ruleSCSCMsg="Tainting Point" tool="jtest"
        // locType="sr" sym="=TempProject/java&lt;org.owasp.benchmark.testcode" lang="java"
        // msg="Injection of data received from servlet request (&quot;param&quot;) to filename
        // setting method" id="924224628" rule="BD.SECURITY.TDFNAMES" config="1" dumpId="37"
        // ruleSAFMsg="Dangerous Method Call" auth="kupsch" FirstElSrcRngOffs="1570"
        // FirstElSrcRngLen="30"
        // FirstElSrcRngFile="/temp/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java"
        // locOffs="1970" locLen="95"
        // locFile="/temp/java/org/owasp/benchmark/testcode/BenchmarkTest00002.java">

        TestCaseResult tcr = new TestCaseResult();
        String ruleId = getAttributeValue("rule", flaw);

        // Now check to see if this rule has an 'original ID' and supply that too. Here's an
        // example:
        // <Rule analyzer="com.parasoft.jtest.flowanalyzer" authTot="0;" authUrg="0;" cat="CWE.79"
        // desc="Protect against HTTP response splitting" id="CWE.79.TDRESP"
        // origId="BD.SECURITY.TDRESP" sev="1" total="0"/>
        // Look up the origId, if any, for the rule specified where the rule's id = ruleId
        Node firstNode = rules.get(0);
        String test = getAttributeValue("id", firstNode);

        Node ruleNode = getNodeWithMatchingKeyAndValue("id", ruleId, rules);
        if (ruleNode == null) {
            System.err.println("WARNING: no matching rule found for ruleId: " + ruleId);
        }

        String origId = getAttributeValue("origId", ruleNode);
        int cweVal = cweLookup(ruleId, origId);

        tcr.setCWE(cweVal);

        String severity = getAttributeValue("sev", flaw);
        tcr.setConfidence(Integer.parseInt(severity));

        String msg = getAttributeValue("msg", flaw);
        tcr.setEvidence(ruleId + "::" + msg);

        String testcase = getAttributeValue("locFile", flaw);
        testcase = testcase.substring(testcase.lastIndexOf('/') + 1);
        if (isTestCaseFile(testcase)) {
            tcr.setActualResultTestID(testcase);
            return tcr;
        }
        return null;
    }

    // https://www.securecoding.cert.org/confluence/display/java/Parasoft
    // https://docs.parasoft.com/display/JTEST20241/CQA+Supported+Rules - Java
    private static int cweLookup(String originalCategory, String origId) {

        int returnValue = -1; // Default if there is an error or no mapping
        int parsedCWENumber = -1; // Default
        boolean foundCWEValue = false;

        String catToUse = originalCategory;
        boolean useOrigIdCategory = false;
        // The 'cat' mappings aren't always accurate so we use the origId 'rule name' instead so
        // we can do our own mappings.
        if (origId != null) {
            catToUse = origId;
            useOrigIdCategory = true;
        }

        // For the Parasoft C/C++ rulesets like: CWE Top 25 2024, the categories returned look
        // like this: CWE-798-a, CWE-119-f, etc.
        char CWEMatchChar = ' '; // Placeholder unused value
        String CWEMatchString = ""; // If value set, then invoke CWE parsing
        String CWECategoryExample = "";

        // Original categories can look like this:
        if (originalCategory.startsWith("CWE-")) {
            CWEMatchChar = '-';
            CWEMatchString = "-";
            CWECategoryExample = "CWE-###-n";
        } else if (originalCategory.startsWith("CWE.")) {
            // For the Parasoft C# rulesets like: CWE Top 25 2024, the categories returned look
            // like this: CWE.94.TDCODE, CWE.200.SENS, etc.
            CWEMatchChar = '.';
            CWEMatchString = ".";
            CWECategoryExample = "CWE.###.NNN";
        }

        // Compute the CWE from the category so we can compare our rule mapping to the CWE they
        // have assigned this rule to.
        if (CWEMatchString.length() > 0) {
            String cweValue = originalCategory.substring(4);
            if (cweValue.contains(CWEMatchString)) {
                cweValue = cweValue.substring(0, cweValue.indexOf(CWEMatchChar));
                try {
                    parsedCWENumber = Integer.parseUnsignedInt(cweValue);
                } catch (NumberFormatException e) {
                    System.err.println(
                            "WARNING: Parasoft CWE finding category expected to look like '"
                                    + CWECategoryExample
                                    + "' but actually looks like: "
                                    + originalCategory);
                }
            } else {
                System.err.println(
                        "WARNING: Parasoft CWE finding category expected to look like '"
                                + CWECategoryExample
                                + "' but actually looks like: "
                                + originalCategory);
            }
        }

        try {
            /* Rules can look like this:
            <Rule analyzer="com.parasoft.jtest.flowanalyzer" authTot="2125;" authUrg="9;" cat="CWE.79" desc="Protect against HTTP response splitting" id="CWE.79.TDRESP" origId="BD.SECURITY.TDRESP" sev="1" total="2125"/>
            */

            // Use the actual rule name to look up the CWE # and return that value.
            foundCWEValue = true; // Set to false in default case if not found.
            switch (catToUse) {
                    // Jtest Java rule mappings:
                case "BD.SECURITY.TDCMD": // Protect against Command injection
                case "SECURITY.WSC.APIBS": // Prevent scripting API from executing untrusted code
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 114) return parsedCWENumber; // Process Control
                    if (parsedCWENumber == 470) return parsedCWENumber; // Unsafe Reflection
                    if (parsedCWENumber == 668)
                        return parsedCWENumber; // Exposure of Resource to Wrong Sphere
                    returnValue = 77; // Generic command injection rather than OS command injection
                    break;
                case "BD.SECURITY.TDFNAMES": // Protect against File names injection
                    returnValue = CweNumber.PATH_TRAVERSAL;
                    break;
                case "BD.SECURITY.TDLDAP": // Protect against LDAP injection
                    returnValue = CweNumber.LDAP_INJECTION;
                    break;
                case "BD.SECURITY.TDRESP": // Protect against HTTP response splitting
                    returnValue = CweNumber.HTTP_RESPONSE_SPLITTING;
                    break;
                case "BD.SECURITY.TDSQL": // Protect against SQL injection
                case "SECURITY.IBA.UPS": // Use 'prepareCall' or 'prepareStatement' instead of
                    // 'createStatement'
                    returnValue = CweNumber.SQL_INJECTION;
                    break;
                case "BD.SECURITY.TDXPATH": // Protect against XPath injection
                    returnValue = CweNumber.XPATH_INJECTION;
                    break;
                case "BD.SECURITY.TDXSS": // Protect against XSS vulnerabilities
                    returnValue = CweNumber.XSS;
                    break;
                case "SECURITY.WSC.SRD": // Use java.security.SecureRandom instead of
                    // java.util.Random or Math.random()
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 328) return parsedCWENumber; // Use of Weak Hash
                    if (parsedCWENumber == 676)
                        return parsedCWENumber; // Use of Potentially Dangerous Function
                    returnValue = CweNumber.WEAK_RANDOM;
                    break;

                case "SECURITY.UEC.SEP": // Always specify error pages in web.xml
                    returnValue = 7; // J2EE Misconfiguration: Missing Custom Error Page
                    break;
                case "SECURITY.BV.SYSP": // Do not access or set System properties
                case "SERVLET.UCO": // Use a Context Object to manage HTTP request parameters
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 601) return parsedCWENumber; // Open Redirect
                    if (parsedCWENumber == 668)
                        return parsedCWENumber; // Exposure of Resource to Wrong Sphere
                    returnValue = 15; // External Control of System or Configuration Settings
                    break;

                case "BD.SECURITY.EACM": // Encapsulate arguments of dangerous methods with a
                    // validation method
                case "BD.SECURITY.TDFILES": // Protect against File contents injection
                case "BD.SECURITY.VPPD": // Validate all dangerous data
                    // These are per Parasoft's CWE mapping
                    returnValue = 20; // Input validation
                    break;

                case "BD.SECURITY.TDXML": // Protect against XML data injection
                    returnValue = 91; // XML Injection
                    break;
                case "BD.SECURITY.TDNET": // Protect against network resource injection
                    returnValue = 99; // Resource Injection
                    break;
                case "PORT.NATV": // Do not use user-defined "native" methods
                case "SECURITY.IBA.NATIW": // Use wrapper methods to secure native methods
                    returnValue = 111; // Direct Use of Unsafe JNI
                    break;
                case "BD.SECURITY.XMLVAL": // Validate untrusted XML using schema or DTD before
                    // reading
                    returnValue = 112; // Missing XML Validation
                    break;
                case "BD.PB.ARRAY": // Avoid accessing arrays out of bounds
                case "BD.SECURITY.ARRAY": // NOT Documented, but assuming its equivalent to above
                case "PB.RE.CAI": // Always check parameters before use in array access
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 131)
                        return parsedCWENumber; // Incorrect Calculation of Buffer Size
                    returnValue = 129; // Improper Validation of Array Index
                    break;
                case "BD.SECURITY.TDINPUT": // Exclude unsanitized user input from format strings
                    returnValue = 134; // Use of Externally-Controlled Format String
                    break;
                case "BD.PB.INTWRAP": // Avoid wraparounds when performing arithmetic integer
                    // operations
                    returnValue = 190; // Integer Overflow or Wraparound
                    break;
                case "PB.LOGIC.AOBO": // Avoid off-by-one errors in loop conditions
                    returnValue = 193; // Off-by-one Error
                    break;

                case "BD.SECURITY.SENS": // Prevent exposure of sensitive data
                case "BD.SECURITY.SSSD": // Safely serialize sensitive data
                case "SECURITY.ESD": // A category not a specific rule. Was used by older versions
                case "SECURITY.ESD.SIO": // Avoid calling print methods System.err or System.out
                case "SECURITY.WSC.ACPST": // Do not call printStackTrace() on Throwable objects
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 311)
                        return parsedCWENumber; // Missing Encryption of Sensitive Data
                    returnValue = 200; // Exposure of Sensitive Data
                    break;
                case "SECURITY.ESD.PEO": // Do not include exception messages in output
                    returnValue = 209; // Generation of Error Messages w/ Sensitive Informatiom
                    break;
                case "SPRING.JDBCTEMPLATE": // Avoid using native JDBC
                    returnValue = 245; // J2EE Bad Practices: Direct Management of Connections
                    break;
                case "SECURITY.WSC.SS": // Do not use sockets in web components
                    returnValue = 246; // J2EE Bad Practices: Direct Use of Sockets
                    break;
                case "BD.PB.EXCEPT": // Always catch exceptions
                    returnValue = 248; // Uncaught Exception
                    break;
                case "PB.LOGIC.CRRV": // Check the return value of methods which read or skip input
                    returnValue = 252; // Unchecked Return Value
                    break;
                case "BD.SECURITY.TDPASSWD": // Protect against using unprotected credentials
                    returnValue = 256; // Plaintext Storage of a Password
                    break;
                case "SECURITY.WSC.HCCS": // Avoid passing hardcoded usernames/passwords/URLs to
                    // database connection methods (Parasoft maps to CWE-798: Hard-coded Creds)
                    returnValue = 259; // Use of Hard-coded Password
                    break;
                case "SECURITY.WSC.HTTPRHA": // Do not rely on IP addresses obtained from HTTP
                    // request headers for authentication
                    returnValue = 290; // Authentication Bypass by Spoofing
                    break;
                case "SECURITY.WSC.VSI": // Properly validate server identity
                    // DRW TODO: See if the 295/297 mapping to Malicious Code IMPROVES Sore or not.
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 287) return parsedCWENumber; // Improper Authentication
                    returnValue = 295; // Improper Certificate Validation
                    break;
                case "SECURITY.WSC.SSM": // Ensure that an appropriate security manager is set (They
                    // also map this to 287, which is another AuthN related CWE)
                    returnValue = 306; // Missing Authentication for Critical Function
                    break;
                case "SECURITY.WSC": // A category not a specific rule. Was used by older versions
                    returnValue = 311; // Failure to encrypt sensitive data
                    break;
                case "SECURITY.WSC.USC": // Use the SSL-enabled version of classes when possible
                    returnValue = 319; // Cleartext Transmission of Sensitive Information
                    break;
                case "SECURITY.WSC.HCCK": // Avoid using hard-coded cryptographic keys
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 506) return parsedCWENumber; // Embedded Malicious Code
                    returnValue = 321; // Use of Hard-coded Cryptographic Key
                    break;
                case "SECURITY.WSC.MCMDU": // MessageDigest objects must process the data with the
                    // 'update' method
                case "SECURITY.WSC.SIKG": // Initialize KeyGenerator instances
                    returnValue = 325; // Missing Cryptographic Step
                    break;
                case "SECURITY.WSC.ICA": // Avoid using insecure algorithms for cryptography
                    returnValue = 328; // Use of Weak Hash
                    break;
                case "SECURITY.WSC.IVR": // Avoid non-random 'byte[]' when using IvParameterSpec
                    returnValue = 329; // Generation of Predictable IV w/ CBC Mode
                    break;
                case "SECURITY.WSC.DNSL": // Avoid DNS Lookups for decision making
                    returnValue = 350; // Reliance on Reverse DNS for Security-Critical Action
                    break;
                case "SECURITY.WSC.ENPP": // Ensure arguments passed to certain methods come from
                    // predefined methods list
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 329)
                        return parsedCWENumber; // Generation of Predictable IV w/ CBC Mode
                    returnValue = 336; // Same Seed in Pseudo-Randmom Number Generator
                    break;
                case "SECURITY.WSC.UOSC": // Use getSecure()/setSecure() to enforce use of secure
                    // cookies
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 614)
                        return parsedCWENumber; // Sensitive Cookie in Session w/out 'Secure'
                    // Attribute
                    returnValue = 352; // CSRF
                    break;
                case "SECURITY.IBA.ATF": // Avoid temporary files
                    returnValue = 377; // Insecure Temporary File
                    break;
                case "CODSTA.BP.EXIT": // Do not call methods which terminates Java Virtual Machine
                case "SECURITY.EAB.JVM": // Do not stop the JVM in a web component
                case "SECURITY.IBA.JVM": // Do not stop the JVM in a web component
                    returnValue = 382; // J2EE Bad Practices: Use of System.exit()
                    break;
                case "SECURITY.DRC.THR": // Do not use threads in web components
                case "TRS.ISTART": // Do not call the 'start()' method directly on Thread class
                    // instances
                    returnValue = 383; // J2EE Bad Practice: Direct Use of Threads
                    break;
                case "SECURITY.UEHL.LGE": // Ensure all exceptions are either logged with a standard
                    // logger or rethrown
                    returnValue = 390; // Detection of Error Condition Without Action
                    break;
                case "CODSTA.EPC.NCE": // Do not catch exception types which are too general or are
                    // unchecked exceptions
                    returnValue = 396; // Declaration of Catch for Generic Exception
                    break;
                case "CODSTA.BP.NTX": // Avoid declaring methods to throw general or unchecked
                    // Exception types
                    returnValue = 397; // Declaration of Throws for Generic Exception
                    break;
                case "BD.EXCEPT.NP": // Avoid NullPointerException
                case "EXCEPT.NCNPE": // Do not catch 'NullPointerException
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 457)
                        return parsedCWENumber; // Use of Uninitialized Variable
                    returnValue = 395; // Don't catch NullPointerException
                    break;
                case "BD.EXCEPT.AN": // Avoid catching generic Exception/Throwable
                    returnValue = 396; // Declaration of Catch for Generic Exception
                    break;

                case "BD.RES.LEAKS": // Ensure resources are deallocated
                case "TRS.UWNA": // Use wait() and notifyAll() instead of polling loops
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 833) return parsedCWENumber; // Deadlock
                    returnValue = 400; // Uncontrolled Resource Consumption
                    break;
                case "JDBC.ODBIL": // Do not open or close JDBC connections in loops
                case "TRS.RLF": // Release Locks in a 'finally' block
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 833) return parsedCWENumber; // Deadlock
                    returnValue = 404; // Improper resource shutdown or release
                    break;
                case "INIT.LV": // Initialize all local variables explicitly at the declaration
                    // statement
                    returnValue = 456; // Missing Initialization of Variable
                    break;
                case "BD.SECURITY.TDRFL": // Protect against Reflection injection
                    returnValue = 470; // Unsafe Reflection
                    break;
                case "BD.EXCEPT.NR": // Avoid NullReferenceException
                    returnValue = 476; // Null Pointer Dereference
                    break;
                case "PB.API.DPRAPI": // Do not use deprecated APIs
                    returnValue = 477; // Use of Obsolete Function
                    break;
                case "PB.PDS": // Provide 'default:' for each 'switch' statement
                    returnValue = 478; // Missing Default Case in Multiple Condition Expression
                    break;
                case "PB.TYPO.ASI": // Avoid assignment within a condition
                    returnValue = 481; // Assigning instead of Comparing
                    break;
                case "CODSTA.BP.BLK": // Provide a '{}' block for conditional statements
                case "PB.CUB.EBI": // Avoid erroneously placing statements outside of blocks
                case "PB.TYPO.EB": // Avoid control statements with empty bodies
                    returnValue = 483; // Incorrect Block Delimitation
                    break;
                case "PB.CUB.SBC": // Do not use a 'switch' statement with a bad 'case'
                case "PB.TYPO.DAV": // Avoid assigning same variable in the fall-through switch case
                    // (TEST TODO: Maybe this should be 484:Omitted Break Statement in Switch"?
                    returnValue = 484; // Omitted Break Statement in Switch
                    break;
                case "SECURITY.BV.AUG": // Inspect usage of 'getName()' from 'java.lang.Class'
                    // object
                    returnValue = 486; // Comparison of Classes by Name
                    break;
                case "OOP.AF": // Avoid "public" "protected"/package-private fields
                    returnValue = 487; // Reliance on Package-level Scope
                    break;
                case "SECURITY.WSC.CLONE": // Make your 'clone()' method 'final' for security
                case "SECURITY.WSC.MCNC": // Make your classes noncloneable
                    returnValue = 491; // Public cloneable() Method without Final (Object Hijack)
                    break;
                case "SECURITY.WSC.INNER": // Make all member classes 'private'
                    returnValue = 492; // Use of Inner Class Containing Sensitive Data
                    break;
                case "SECURITY.ESD.SIF": // Inspect instance fields of serializable objects to make
                    // sure they will not expose sensitive information
                case "SECURITY.WSC.SER": // Make your classes nonserializeable
                    returnValue = 499; // Serializable Class Containing Sensitive Data
                    break;
                case "SECURITY.EAB.SPFF": // Inspect 'static' fields which may have intended to be
                    // declared 'static final
                    returnValue = 500; // Public Static Field Not Marked Final
                    break;
                case "SERIAL.VOBD": // Validate objects before deserialization
                    returnValue = 502; // Deserialization of Untrusted Data
                    break;
                case "SECURITY.WSC.RDM": // Inspect 'Random' objects or 'Math.random()' methods that
                    // could indicate areas where malicious code has been placed
                    returnValue = 511; // Logic/Time Bomb
                    break;
                case "BD.SECURITY.TDLOG": // Avoid passing unvalidated binary data to log methods
                case "SECURITY.ESD.CONSEN": // Do not log confidential or sensitive info
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 117)
                        return parsedCWENumber; // Improper Output Neutralization for Logs
                    returnValue = 532; // Insertion of Sensitive Info into Log File
                    break;
                case "TRS.IASF": // Inspect accesses to "static" fields which may require
                    // synchronization
                    returnValue = 543; // Use of Singleton Pattern w/Out Synchronization
                    break;
                case "CODSTA.ORG.TODOJAVA": // Ensure that comments do not contain task tags
                    returnValue = 546; // Suspicious Comment
                    break;

                case "PB.USC.AES": // Avoid empty statements
                case "PB.USC.SAFL": // Avoid assignments/initializations to fields and/or local
                    // variables
                case "PB.USC.UIF": // Avoid unreachable 'else if' and 'else' cases
                case "UC.AURV": // Avoid local variables that are never read
                case "UC.EF": // Avoid empty finalize() methods
                case "UC.PM": // Avoid unused "private" methods
                case "UC.UCIF": // Avoid unnecessary 'if' statements
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 563) // For: "UC.AURV"
                    return parsedCWENumber; // Variable assigned but not used
                    returnValue = 561; // CWE-561: Dead Code
                    break;

                case "BD.PB.VOVR": // Avoid unused values
                case "GLOBAL.UPPF": // Avoid globally unused "public/protected" fields
                case "UC.PF": // Avoid unused "private" fields
                case "UC.UP": // Avoid unused parameters
                    returnValue = 563; // Variable assigned but not used
                    break;
                case "GC.FCF": // Call super.finalize() from finalize()
                case "GC.IFF": // Call super.finalize() in the finally block of finalize() methods
                    returnValue = 568; // finalize() Method Without super.finalize()
                    break;
                case "BD.PB.CC": // Avoid conditions that always evaluate to the same value
                    returnValue =
                            569; // Should be more specific. Either always true or false 571/570
                    break;

                case "TRS.IRUN": // Do not call the 'run()' method directly on classes extending
                    // 'java.lang.Thread' or implementing 'java.lang.Runnable'
                    returnValue = 572; // Call to Thread run() instead of start()
                    break;
                case "PB.API.ONS": // Ensure method arguments are serializable
                case "SERIAL.SNSO": // Do not store non-serializable objects as HttpSession
                    // attributes
                    returnValue =
                            579; // J2EE Bad Practices: Non-serializable Object Stored in Session
                    break;
                case "CODSTA.EPC.SCLONE": // Call super.clone() in all clone() methods
                    returnValue = 580; // clone() Method Without super.clone()
                    break;
                case "CODSTA.OIM.OVERRIDE": // Override 'Object.hashCode()' when you override
                    // 'Object.equals()
                    returnValue =
                            581; // Object Model Violation: Just one of Equals and Hashcode Defined
                    break;
                case "PB.CUB.IMM": // Ensure 'static' 'final' fields are immutable
                case "PB.CUB.PSFA": // Avoid using 'public static final' array fields
                    returnValue = 582; // Array Declared Public, Final, and Static
                    break;
                case "UC.SNE": // Avoid empty synchronized statements
                    returnValue = 585; // Empty synchronized block
                    break;
                case "GC.NCF": // Do not call finalize() explicitly
                    returnValue = 586; // Explicit Call to Finalize()
                    break;
                case "PB.CUB.UEIC": // Do not use == or != to compare objects
                    returnValue = 597; // Use of Wrong Operator in String Comparison
                    break;
                case "SERVLET.CETS": // Catch all exceptions which may be thrown in Servlet methods
                    returnValue = 600; // Uncaught Exception in Servlet
                    break;
                case "SECURITY.IBA.VRD": // Encapsulate all redirect and forward URLs with a
                    // validation function
                    returnValue = 601; // Open Redirect
                    break;
                case "PORT.HCNA": // Do not hard-code IP addresses and port numbers
                    returnValue = 605; // Multiple Binds to the Same Port
                    break;
                case "PB.CUB.RMO": // Avoid referencing mutable fields
                    returnValue = 607; // Public Static Final Field References Mutable Object
                    break;
                case "TRS.DCL": // Avoid unsafe implementations of 'double-checked locking'
                    returnValue = 609; // Double-Checked Locking
                    break;
                case "SECURITY.IBA.RUIM": // Ensure proper session expiration
                case "SECURITY.UEC.STTL": // Ensure that sessions are configured to time out in
                    // 'web.xml'
                    returnValue = 613; // Insufficient Session Expiration
                    break;
                case "CODSTA.ORG.ASSERT": // Do not use assertions in production code
                    returnValue = 617; // Reachable Assertion
                    break;
                case "SECURITY.IBA.XPIJ": // Avoid XPath injection when evaluating XPath queries
                    returnValue = 643; // XPath Injection
                    break;
                case "PB.CLOSE": // Unrestricted lock resource
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 772)
                        return parsedCWENumber; // Missing Release of Resource after Effective
                    // Lifetime
                    returnValue = 667; // Improper Locking
                    break;
                case "PB.LOGIC.FLRC": // Avoid infinite recursive methods
                    returnValue = 674; // Uncontrolled Recursion
                    break;
                case "CODSTA.READ.ANL": // Avoid using negative logic in if-else statement
                    returnValue = 691; // Insufficient Control Flow Management
                    break;
                case "OPT.CPTS": // Do not convert a value to a String by concatenating the empty
                    // String
                    returnValue = 704; // Incorrect Type Conversion or Cast
                    break;

                case "SECURITY.WSC.ASNF": // Avoid implicit file creation when a String is passed as
                    // an argument
                case "SECURITY.WSC.CFAP": // Create files with appropriate access permissions
                case "SECURITY.WSC.IDP": // Avoid setting the write or execute file permissions to
                    // unintended users
                    returnValue = 732; // Incorrect Permission Assignment for Critical Resource
                    break;
                case "GLOBAL.DPAM": // Declare package-private methods as inaccessible as possible
                case "GLOBAL.DPPM": // Declare "public/protected" methods as inaccessible as
                    // possible
                case "GLOBAL.SPAM": // Declare a package-private method "final" if it is not
                    // overridden
                    returnValue = 749; // Exposed Dangerous Method or Function
                    break;
                case "TRS.CIET": // Do not catch InterruptedException except in classes extending
                    // Thread
                    returnValue = 755; // Improper Handling of Exceptional Conditions
                    break;
                case "SECURITY.WSC.MDSALT": // Use hash functions with a salt
                    returnValue = 759; // Use of One-Way Hash without Salt
                    break;
                case "BD.TRS.DLOCK": // Avoid Double Locking
                case "BD.TRS.LOCK": // Do not abandon unreleased locks (TODO: Or Maybe 'don't
                    // care'??
                    returnValue = 764; // Multiple Locks of a Critical Resource
                    break;
                case "SECURITY.UEHL": // Insecure logging category
                    returnValue = 778; // Insufficient Logging
                    break;
                case "SECURITY.WSC.BUSSB": // Prevent external processes from blocking on output or
                    // error streams
                    returnValue = 806; // Buffer Access Using Size of Source Buffer
                    break;

                case "BD.TRS.ORDER": // Do not acquire locks in a different order
                case "BD.TRS.TSHL": // Do not use blocking methods while holding a lock
                case "TRS.CSFS": // Do not cause deadlocks by calling a synchronized method from a
                    // synchronized method
                case "TRS.STR": // Do not perform synchronization nor call semaphore methods on an
                    // Object's 'this' reference
                case "TRS.TSHL": // Do not call Thread.sleep() while holding a lock
                    returnValue = 833; // Deadlock
                    break;
                case "CODSTA.READ.PCIF": // Declare 'for' loops with an initializer, conditional,
                    // and updater statements
                case "PB.LOGIC.AIL": // Avoid infinite loops
                    returnValue = 835; // Infinite Loop
                    break;
                case "INTER.SEO": // Avoid calling methods and constructors which do not allow you
                    // to specify a character encoding option
                    returnValue = 838; // Inappropriate Encoding for Output Context
                    break;
                case "SECURITY.WSC.SCHTTP": // Mark cookies as HttpOnly
                    returnValue = 1004; // Sensitive Cookie Without 'HttpOnly' Flag
                    break;
                case "SECURITY.EAB.OROM": // Implement 'readObject()' and 'writeObject()' for all
                    // 'Serializable' classes
                    returnValue = 1066; // Missing Serialization Control Element
                    break;
                case "CODSTA.READ.CEB": // Comment empty blocks
                    returnValue = 1071; // Empty Code Block
                    break;
                case "PORT.DNHCP": // Do not hard code an absolute pathname when calling a
                    // constructor from the 'File' class
                case "PORT.LNSP": // Do not hard code '\n' or '\r' as a line separator
                    returnValue = 1102; // Reliance on Machine-Dependent Data Representation
                    break;
                case "CODSTA.READ.USN": // Avoid literal constants
                    returnValue = 1106; // Insufficient Use of Symbolic Constants
                    break;
                case "FORMAT.MCH": // Include a meaningful file header comment in every source file
                    returnValue = 1115; // Source Code Element w/out Standard Prologue
                    break;
                case "CODSTA.READ.DVCU": // Declare variables as close as possible to where they are
                    // used
                    returnValue = 1126; // Declaration of Variable with Unnecessarily Wide Scope
                    break;
                case "CODSTA.READ.ABUB": // Don't rely on automatic boxing/unboxing of primitive
                    // types
                    returnValue = 1235; // Incorrect Use of Autoboxing for Performance Crit Ops
                    break;
                case "BD.PB.PBIOS": //
                    returnValue = 1322; // Blocking code in single-threaded, non-blocking context
                    break;
                case "SECURITY.WSC.UHTTPS": // Use HTTPS instead of HTTP
                    returnValue = 1428; // Reliance on HTTP instead of HTTPS
                    break;

                    // Don't know how to map these properly. I think newer Parasoft versions report
                    // more specific values, i.e., the rule name, not just the CATegory.
                    //            case "SECURITY.IBA": // This is a category. The rule is more
                    // specific, e.g., rule="SECURITY.IBA.VPPD"
                    //            case "SECURITY.BV": - Guessing this is a category too.

                case "CODSTA.EPC.CLNC": // Do not use constructors in the clone() method
                case "EXCEPT.AEFC": // Do not abuse exceptions as flow control statements
                case "EXCEPT.NTERR": // Do not throw exception types which are too general or are
                    // unchecked exceptions

                    // Note: All the OPT. rules are 'optimizations' not security issues.
                case "OPT.CTLV": // Do not use a 'private' field that is accessed in only 1 method.
                    // Change it to a local variable.
                case "OPT.UNC": // Avoid unnecessary casting

                case "PB.LOGIC.OAMC": // Ensure objects used in a loop's condition are properly
                    // accessed within loop body (TODO: Should be CWE 89??)
                case "PB.NUM.CLP": // Do not case primitive types to lower precision
                case "PB.TYPO.WT": // Ensure args passed to Java wrapper classes do not contain
                    // typos
                case "SECURITY.WSC.ARXML": // Process XML and HTML with a library instead of raw
                    // text
                case "SERIAL.RWAF": // Ensure all fields are assigned by readObject() and written
                    // out by writeObject()
                case "UC.AURCO": // Avoid collection objects that are never read (TODO: Maybe should
                    // be: CWE789 Mem Alloc w/Excessive Size)
                    returnValue = CweNumber.DONTCARE;
                    break;

                    //// CSharp specific findings - Reference pages below:
                    // https://docs.parasoft.com/display/DOTTEST20241/CQA+Supported+Rules - CSharp
                    // https://docs.parasoft.com/display/DOTTEST20252/.NET+Core+Supported+Rules -
                    // CSharp
                case "BRM.APNFT": // Always provide names for threads
                case "BRM.HBCM": // Avoid hiding methods from base classes
                    // TODO: Fix the bug in C# test cases causing the following??
                case "BD.PB.STRNULL": // Do not append null value to strings - FIXME (In CWE 256,
                    // 313, 314, 315, 319)
                case "CMUG.MU.RETVAL": // NOT DOCUMENTED - FIXME (In CWE 284, 440)
                case "PB.AIRC": // NOT DOCUMENTED - FIXME (1x in CWE 667)
                case "PB.DNUP": // NOT DOCUMENTED - FIXME (In CWE 117, 129, 369, 396, 400, 440,
                    // -->476, 566, 606, 681)
                case "PB.II.NIE": // NOT DOCUMENTED - FIXME (2x in CWE 582)
                case "TRS.THREADSLEEP": // NOT DOCUMENTED - FIXME (In CWE 400)
                    returnValue = CweNumber.DONTCARE;
                    break;

                case "ROSLYN.SCS.INJ.SCS0018": // Path Traversal
                    returnValue = CweNumber.PATH_TRAVERSAL;
                    break;
                case "ROSLYN.MSNA.SECURITY.CA3005": // Review code for LDAP injection
                    // vulnerabilities
                case "ROSLYN.SCS.INJ.SCS0031": // LDAP injection
                    returnValue = CweNumber.LDAP_INJECTION;
                    break;
                case "BD.SECURITY.TDSQLC": // Protect against SQL injection
                case "ROSLYN.SCS.INJ.SCS0002": // SQL injection
                case "ROSLYN.MSNA.SECURITY.CA2100": // Review SQL queries for security
                    // vulnerabilities
                case "ROSLYN.MSNA.SECURITY.CA3001": // Review code for SQL injection vulnerabilities
                    returnValue = CweNumber.SQL_INJECTION;
                    break;
                case "ROSLYN.SCS.INJ.SCS0029": // desc=Cross-Site Scripting (XSS)
                    returnValue = CweNumber.XSS; // CWE-79: XSS
                    break;
                case "ROSLYN.MSNA.SECURITY.CA3008": // Review code for XPath injection
                    // vulnerabilities
                case "ROSLYN.SCS.INJ.SCS0003": // XPath injection
                    returnValue = CweNumber.XPATH_INJECTION;
                    break;

                case "SEC.VPPD": // Validate all dangerous data (Not in dotTEST docs, using Java
                    // mapping)
                    returnValue = 20; // Input validation
                    break;
                case "BD.SECURITY.TDCODE": // Validate potentially tainted data before it is used in
                    // methods that generate code
                    returnValue = 94; // Code Injection
                    break;
                case "BD.PB.INTDL": // Avoid data loss when converting between integer types
                case "CT.ECLSII": // Avoid explicit conversions of integrals to integrals of smaller
                    // size if the conversion may cause data truncation
                    returnValue = 197; // Numeric Truncation Error
                    break;
                case "ROSLYN.MSNA.SECURITY.CA3004": // Review code for information disclosure
                    // vulnerabilities
                    returnValue = 200; // Exposure of Sensitive Info to Unauthorized Actor
                    break;
                case "ROSLYN.SCS.PWM.SCS0015": // Hardcoded Password
                case "SPR.HARDCONN": // Avoid hard coded connection strings (Parasoft maps to
                    // CWE-798: Hard-coded Creds)
                    returnValue = 259; // Use of Hard-coded Password
                    break;
                case "ROSLYN.MSNA.SECURITY.CA5390": // Do not hard-code encryption key
                    returnValue = 321; // Use of Hard-coded Cryptographic Key
                    break;
                case "ROSLYN.MSNA.SECURITY.CA5350": // Do Not Use Weak Cryptographic Algorithms
                case "ROSLYN.MSNA.SECURITY.CA5351": // Do Not Use Broken Cryptographic Algorithms
                case "ROSLYN.SCS.CRPGH.SCS0010": // Weak cipher algorithm
                    returnValue = 327; // Use of Broken/Risky Cryptographic Algorithm
                    break;
                case "ROSLYN.SCS.CRPGH.SCS0006": // Weak hashing function
                    returnValue = 328; // Use of Weak Hash
                    break;
                case "ROSLYN.MSNA.SECURITY.CA5394": // Do not use insecure randomness
                case "ROSLYN.SCS.CRPGH.SCS0005": // Weak Random Number Generator
                case "SEC.USSCR": // Use System.Security.Cryptography.RandomNumberGenerator instead
                    // of System.Random
                    returnValue = 338; // Cryptographically Weak PRNG
                    break;
                case "SEC.WEB.IIPHEU": // Do not rely on reverse DNS resolution for security
                    // decisions
                    returnValue = 350; // Reliance on Reverse DNS for Security-Critical Action
                    break;
                case "BD.TRS.DIFCS": // Variable should be used in context of single critical
                    // section
                    returnValue = 362; // Race Condition (Using Parasoft's CWE mapping for this)
                    break;
                case "BD.PB.TMTC": // NOT DOCUMENTED - FIXME
                    returnValue = 366; // Race Condition within a Thread
                    break;
                case "BD.PB.ZERO": // Avoid Division by zero
                    returnValue = 369; // Divide by Zero
                    break;
                case "CS.EXCEPT.RETHROW": // Avoid clearing stack trace while rethrowing exceptions
                    // - FIXME (In 390, 396)
                    returnValue = 390; // Detection of Error Condition Without Action
                    break;
                case "EXCEPT.NCNRE": // Do not catch 'NullReferenceException'
                    returnValue = 395; // Don't catch NullPointerException
                    break;
                case "EXCEPT.NCSAE": // Avoid the use of 'catch' on 'Exception', 'SystemException'
                    // or 'ApplicationException
                case "ROSLYN.MSNA.DESIGN.CA1031": // Do not catch general exception types
                    returnValue = 396; // Don't catch Generic Exception
                    break;
                case "EXCEPT.NTSAE": // Avoid throwing 'Exception', 'SystemException' or
                    // 'ApplicationException'
                    returnValue = 397; // Don't throw Generic Exception
                    break;
                case "SEC.PBRTE": // Always specify absolute path to execute commands
                    returnValue = 426; // Untrusted Search Path
                    break;
                case "PB.INOE": // Use String.IsNullOrEmpty to check if a string is null or empty
                    returnValue = 476; // NULL Pointer Dereference
                    break;
                case "CS.PB.DEFSWITCH": // Provide 'default:' for each 'switch' statement
                    returnValue = 478; // Missing Default Case in Multiple Condition Expression
                    break;
                case "SEC.AUIC": // Avoid using public inner classes to prevent access from
                    // untrusted classes
                    returnValue = 492; // Use of Inner Class Containing Sensitive Data
                    break;
                case "SEC.IREC": // Do not execute external code without integrity check
                    returnValue = 494; // Download of Code Without Integrity Check
                    break;
                case "ROSLYN.MSNA.SECURITY.CA2300": // Do not use insecure deserializer
                    // BinaryFormatter
                    returnValue = 502; // Deserialization of Untrusted Data
                    break;
                case "BD.SECURITY.SENSLOG": // Avoid passing sensitive data to functions that write
                    // to log files
                    returnValue = 532; // Insertion of Sensitive Info into Log File
                    break;
                case "PB.II.TODO": // Ensure that comments do not contain task tags
                    returnValue = 546; // Suspicious Comment
                    break;

                case "CS.BRM.BEB": // Avoid block statements with empty bodies
                case "CS.PB.IEB": // Avoid initialization statements with empty bodies
                case "CS.PB.ANIL": // Avoid non-iterable loops
                case "CS.PB.CEB": // Avoid conditional statements with empty bodies
                case "CS.PB.EEB": // Avoid try, catch, finally, and using stmts w/ empty bodies
                case "CS.PB.USC.CC": // Avoid Unreachable Code in condition
                case "CS.PB.USC.UC": // Avoid Unreachable Code
                    returnValue = 561; // Dead Code
                    break;

                case "ROSLYN.SCS.OTHER.SCS0027": // Open Redirect
                    returnValue = 601; // Open Redirect
                    break;
                case "ROSLYN.MSNA.SECURITY.CA3075": // Insecure DTD processing in XML
                case "ROSLYN.MSNA.SECURITY.CA5372": // Use XmlReader for XPathDocument constructor
                    returnValue = 611; // XXE
                    break;
                case "ROSLYN.SCS.CKS.SCS0008": // Cookie Without SSL Flag
                    returnValue = 614; // Sensitive Cookie Without 'Secure' Attribute
                    break;
                case "SEC.ATA": // Do not use the Trace.Assert() method in production code
                    returnValue = 617; // Reachable Assertion
                    break;
                case "BD.TRS.MUTEX": // Do not abandon unreleased mutexes
                    returnValue = 667; // Improper Locking
                    break;
                case "BD.PB.DISP": // Do not use disposed resources (In CWE 675)
                    returnValue =
                            675; // Multiple Operations on Resource in Single-Operational Context
                    break;
                case "ROSLYN.MSNA.SECURITY.CA2301": // Do not call BinaryFormatter.Deserialize
                    // without first setting BinaryFormatter.Binder
                case "SEC.APDM": // Avoid using potentially dangerous methods
                    returnValue = 676; // Use of Potentially Dangerous Function
                    break;
                case "BD.PB.INTVC": // Avoid value change when converting between integer types
                case "CT.ECLTS": // Avoid explicit conversions between data types if the conversion
                    // may cause data loss or unexpected results
                    returnValue = 681; // Incorrect Conversion between Numeric Types
                    break;
                case "SEC.LGE": // Ensure all exceptions are logged or rethrown
                    returnValue = 703; // Improper Check or Handling of Exceptional Conditions
                    break;
                case "SEC.ADLL": // Inspect calls to dynamically load libraries
                    returnValue = 829; // Inclusion of Functionality from Untrusted Control Sphere
                    break;
                case "ROSLYN.MSNA.SECURITY.CA5396": // Set HttpOnly to true for HttpCookie
                case "ROSLYN.SCS.CKS.SCS0009": // Cookie Without HttpOnly flag
                    returnValue = 1004; // Missing HttpOnly on Sensitive Cookies
                    break;
                case "CS.CDD.DUPU": // Avoid duplicate using statements
                    returnValue = 1041; // Use of Redundant Code
                    break;

                    //// C/C++ specific findings - Reference pages below:
                    // https://docs.parasoft.com/display/CPPDESKV1034/Built-in+Static+Analysis+Rules
                    // (Defines rule categories but not individual rules)
                    // https://docs.parasoft.com/display/CPPTEST20252/CQA+Supported+Rules - CAN'T
                    // FIND

                    // Under cpptest/manuals/ is: cpptest_rules.pdf

                case "BD-SECURITY-TDFNAMES": // Protect against File names injection
                    returnValue = CweNumber.PATH_TRAVERSAL;
                    break;
                case "BD-SECURITY-TDCMD": // Protect against Command injection
                    returnValue = 77; // Generic command injection rather than OS command injection
                    break;

                case "CODSTA-203": // Do not hard code string literals (Parasoft maps to CWE-798-a)
                case "OPT-14": // Pass objects by reference instead of by value
                    returnValue = CweNumber.DONTCARE;
                    break;

                case "BD-PB-ARRAY": // Avoid accessing arrays and pointers out of bounds
                case "BD-SECURITY-ARRAY": // Avoid tainted data in array indexes
                case "CODSTA-143": // Suspicious use of 'strcpy' w/out checking size of source
                    // buffer.
                    returnValue = 119; // Improper Restriction of Operations within Bounds of Memory
                    // Buffer
                    break;
                case "BD-PB-OVERFRD": // Avoid overflow when reading from a buffer
                case "BD-PB-OVERFNZT": // Avoid overflow due to reading a not zero terminated string
                case "BD-SECURITY-OVERFRD": // Avoid buffer read overflow from tainted data
                    returnValue = 125; // Out-of-bounds Read
                    break;
                case "BD-SECURITY-TDINPUT": // Exclude unsanitized user input from format strings
                    returnValue = 134; // Use of Externally-Controlled Format String
                    break;
                case "BD-PB-NAUNF": // Do not read the value of a non-active union field
                case "BD-PB-PTRARR": // "A pointer operand and any pointer resulting from pointer
                    // arithmetic using that operand shall both address elements of
                    // the same array
                    returnValue = 188; // Reliance on Data/Memory Layout
                    break;
                case "BD-PB-INTDL": // Avoid data loss when converting between integer types
                case "BD-PB-INTUB": // Avoid signed integer overflows
                case "BD-PB-INTWRAP": // Avoid wraparounds when performing arith integer operations
                case "BD-SECURITY-TDINTOVERF": // Avoid potential integer overflow/underflow
                case "MISRA-048_a": // Avoid possible int overflow in expressions where result is
                    // cast to a wider integer type
                    returnValue = 190; // Integer Overflow or Wraparound
                    break;
                case "BD-API-STRSIZE": // The size_t argument passed to any function in string.h
                    // shall have an appropriate value
                    returnValue = 194; // Unexpected Sign Extension
                    break;
                case "BD-API-NEGPARAM": // Do not pass negative values to functions expecting
                    // non-negative arguments
                case "BD-PB-INTVC": // Avoid value change when converting between integer types
                    returnValue = 195; // Signed to Unsigned Conversion Error
                    break;
                case "MISRA-043": // Implicit conversions from wider to narrower integral type which
                    // may result in a loss of information shall not be used
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 704) return parsedCWENumber;
                    returnValue = 196; // Unsigned to Signed Conversion Error
                    break;
                case "BD-SECURITY-TDCONSOLE": // Avoid printing tainted data to output console
                case "SECURITY-15": // Do not print potentially sensitive info from an app error
                    // into exception messages
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 526) return parsedCWENumber;
                    returnValue = 200; // Exposure of Sensitive Info to Unauthorized Actor
                    break;
                case "BD-PB-FGETS": // Reset strings on fgets() or fgetws() failure
                    returnValue = 226; // Sensitive Info in Resource Not Removed Before Reuse
                    break;
                case "SECURITY-16": // Never use gets()
                    returnValue = 242; // Use of Inherently Dangerous Function
                    break;
                case "BD-SECURITY-SENSFREE": // Sensitive data should be cleared before being
                    // deallocated
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 591) return parsedCWENumber;
                    returnValue = 244; // Heap Inspection
                    break;
                case "BD-PB-CHECKRETGEN": // Always check the returned value of non-void function
                    returnValue = 252; // Unchecked Return Value
                    break;
                case "SECURITY-02": // The random number generator functions 'rand()' and 'srand()'
                    // should not be used
                    returnValue = 338; // Weak Random
                    break;
                case "BD-TRS-FRC": // Avoid race conditions while accessing files
                case "SECURITY-19": // Usage of functions prone to race is not allowed
                    returnValue = 362; // Race Condition
                    break;
                case "BD-PB-SIGHAN": // Properly define signal handlers
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 479) return parsedCWENumber;
                    returnValue = 364; // Signal Handler Race Condition
                    break;
                case "BD-PB-ZERO": // Avoid division by zero
                    returnValue = 369; // Divide by Zero
                    break;
                case "SECURITY-39": // Use secure temporary file name functions
                    returnValue = 377; // Insecure Temporary File
                    break;
                case "EXCEPT-25": // Empty 'catch' blocks should not be used
                    returnValue = 390; // Detection of Error Condition Without Action
                    break;
                case "BD-PB-ERRNO": // Properly use errno value
                    returnValue = 391; // Unchecked Error Condition
                    break;
                case "EXCEPT-26": // Avoid using catch-all exception handlers
                    returnValue = 396; // Declaration of Catch for Generic Exception
                    break;
                case "BD-RES-STACKLIM": // Don't create vars on stack above defined limits
                    returnValue = 400; // Uncontrolled Resource Consumption
                    break;
                case "BD-RES-LEAKS": // Ensure resources are freed
                    returnValue = 404; // Improper Resource Shutdown or Release
                    break;
                case "MRM-37": // Declare a copy assignment operator for classes with dynamically
                    // allocated memory
                case "MRM-38": // Declare a copy constructor for classes with dynamically allocated
                    // memory
                    returnValue = 415; // Double Free
                    break;
                case "BD-PB-WRAPESC": // Do not point to wrapped object that has been freed
                case "BD-RES-FREE": // Do not use resources that have been freed
                case "MRM-31": // Freed memory shouldn't be accessed under any circumstances
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 675) return parsedCWENumber;
                    returnValue = 416; // Use After Free
                    break;
                case "BD-SECURITY-TDENV": // Protect against environment injection
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 74) return parsedCWENumber;
                    returnValue = 427; // Uncontrolled Search Path Element
                    break;
                case "BD-PB-NOEXCEPT": // Avoid throwing exceptions from functions that are declared
                    // not to throw
                    returnValue = 440; // Expected Behavior Violation
                    break;
                case "BD-PB-NOTINIT": // Avoid use before initialization
                case "INIT-06": // All member variables should be initialized in constructor
                    returnValue = 457; // Use of Uninitialized Variable
                    break;
                case "MRM-45": // Do not use sizeof operator on pointer type to specify the size of
                    // the memory to be allocated via 'malloc', 'calloc' or 'realloc'
                    // function
                    returnValue = 467; // Use of sizeof() on a Pointer Type
                    break;
                case "CODSTA-189": // Do not add or subtract a scaled integer to a pointer
                    returnValue = 468; // Incorrect Pointer Scaling
                    break;
                case "BD-PB-PTRSUB": // Do not subtract two pointers that do not address elements of
                    // the same array
                    returnValue = 469; // Use of Pointer Subtraction to Determine Size
                    break;
                case "BD-PB-OVERLAP": // An object shall not be assigned or copied to an overlapping
                    // object
                    returnValue = 475; // Undefined Behavior for Input to API
                    break;
                case "BD-PB-NP": // Avoid Null Pointer Dereferencing
                    returnValue = 476; // Null Pointer Dereference
                    break;
                case "CODSTA-35": // Always provide a default branch for switch statements
                    returnValue = 478; // Missing Default Case in Multiple Condition Expression
                    break;
                case "CODSTA-309": // A conversion to pointer-to-function from a function type or
                    // class type shall only occur in appropriate contexts
                    returnValue = 480; // Use of Incorrect Operator
                    break;
                case "CODSTA-138": // The result of an assignment operator should not be used
                    returnValue = 481; // Assigning instead of Comparing
                    break;
                case "MISRA2004-14_2": // All non-null statements shall either have at least one
                    // side-effect however executed or cause control flow to
                    // change
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 398) return parsedCWENumber;
                    returnValue = 482; // Comparing instead of Assigning
                    break;
                case "MISRA2004-14_9": // The statement forming the body of an 'if' or 'else'
                    // statement should be a compound statement
                    returnValue = 483; // Incorrect Block Delimitation
                    break;
                case "CODSTA-149": // Missing break statement between cases in a switch statement
                    returnValue = 484; // Omitted Break Statement in Switch
                    break;
                case "OOP-18": // Avoid "public" data members
                    returnValue = 500; // Public Static Field Not Marked Final
                    break;
                case "BD-SECURITY-SENSLOG": // Avoid passing sensitive data to functions that write
                    // to log files
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 535) return parsedCWENumber;
                    returnValue = 534; // Info Exposure Through Debug Log Files
                    break;
                case "BD-PB-UCMETH": // Avoid unreachable methods
                case "MISRA2004-14_1_b": // There shall be no unreachable code after 'return',
                    // 'break', 'continue', 'goto', 'throw' statements, and
                    // after calls to functions with the 'noreturn' attribute
                case "MISRA2004-14_1_c": // There shall be no unreachable code in
                    // "if/else/while/for" block
                case "OPT-22": // Useless 'case' and 'default' clauses should not be used
                case "OPT-32_b": // Functions with void return type shall not be empty
                case "OPT-35": // Do not assign a variable to itself
                case "OPT-49": // Null statements should not be used
                case "OPT-50": // Empty compound statements should not be used
                case "OPT-51": // Avoid using 'if' statements with empty bodies
                    returnValue = 561; // Dead Code
                    break;
                case "MISRA2004-17_6_a": // The address of an object with automatic storage shall
                    // not be returned from a function
                    returnValue = 562; // Return of Stack Variable Address
                    break;
                case "BD-PB-VOVR": // Avoid unused values
                    returnValue = 563; // Assign to Variable without Use
                    break;
                case "BD-PB-CC": // Avoid conditions that always evaluate to the same value
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 665) return parsedCWENumber;
                    returnValue =
                            569; // Should be more specific. Either always true or false 571/570
                    break;
                case "BD-SECURITY-TDLOOP": // Validate potentially tainted data before use in
                    // controlling expression of a loop
                case "SECURITY-38": // Untrusted data is used as a loop boundary
                    returnValue = 606; // Unchecked Input for Loop Condition
                    break;
                case "CODSTA-199": // Do not use assertions
                    returnValue = 617; // Reachable Assertion
                    break;
                case "BD-TRS-LOCK": // Do not abandon unreleased locks
                    returnValue = 667; // Improper Locking
                    break;
                case "BD-CO-ITMOD": // Do not modify container while iterating over it
                    returnValue = 672; // Operation on Resource After Expiration or Release
                    break;
                case "BD-PB-INFREC": // Avoid infinite recursion
                    returnValue = 674; // Uncontrolled Recursion
                    break;
                case "PB-50": // The number of format specifiers in the format string and the number
                    // of corresponding arguments in the invocation of a string formatting
                    // function should be equal
                    returnValue = 685; // Function Call w/ Incorrect Number of Arguments
                    break;
                case "PB-45": // There should be no mismatch between the '%s' and '%c' format
                    // specifiers in the format string and their corresponding arguments
                    // in the invocation of a string formatting function
                    returnValue =
                            688; // Function Call w/ Incorrect Variable or Reference as Argument
                    break;
                case "CODSTA-126": // A cast shall not be performed between a pointer to object type
                    // and a pointer to a different object type
                case "CODSTA-127_b": // A conversion should not be performed between a pointer to
                    // object type and an integer type other than 'uintptr_t'
                case "CODSTA-128": // A conversion should not be performed from pointer to void into
                    // pointer to object
                case "CODSTA-129_a": // A cast shall not be performed between pointer to void and an
                    // arithmetic type
                case "MISRA-043_c": // Implicit conversions from integral to floating type which may
                    // result in a loss of information shall not be used
                    returnValue = 704; // Incorrect Type Conversion or Cast
                    break;
                case "CODSTA-147": // Pointer should not be compared with NULL using relational
                    // operators <, >, >=, <=
                    returnValue = 754; // Improper Check for Unusual or Exceptional Conditions
                    break;
                case "BD-RES-INVFREE": // Do not free resources using invalid pointers
                    returnValue = 761; // Free of Pointer not at Start of Buffer
                    break;
                case "BD-RES-BADDEALLOC": // Properly deallocate dynamically allocated resources
                case "CODSTA-CPP-04": // Constructors allowing for conversion should be made
                    // explicit
                case "MRM-35": // Never provide brackets ([]) for delete when deallocating
                    // non-arrays
                case "MRM-36": // Always provide empty brackets ([]) for delete when deallocating
                    // arrays
                    returnValue = 762; // Mismatched Memory Management Routines
                    break;
                case "BD-SECURITY-TDALLOC": // Validate potentially tainted data before it is used
                    // to determine the size of memory allocation
                    returnValue = 770; // Allocation of Resources w/Out Limits or Throttling
                    break;
                case "BD-SECURITY-OVERFWR": // Avoid buffer write overflow from tainted data
                case "BD-PB-OVERFWR": // Avoid overflow when writing to a buffer
                case "BD-PB-PATHBUF": // Ensure output buffer is large enough when using path
                    // manipulation functions
                    // If matches, return this CWE since it doesn't map to the CWE below
                    if (parsedCWENumber == 126) return parsedCWENumber; // Buffer Over-Read
                    if (parsedCWENumber == 127) return parsedCWENumber; // Buffer Under-Read
                    if (parsedCWENumber == 194) return parsedCWENumber; // Unexpected Sign Extension
                    if (parsedCWENumber == 785)
                        return parsedCWENumber; // Use of Path Manip Function w/Out Max-Sized Buffer
                    returnValue = 787; // Out-of-bounds Write
                    break;
                case "BD-TRS-REVLOCK": // Do not release a lock that has not been acquired
                    returnValue = 832; // Unlock of a Resource that is not Locked
                    break;
                case "CODSTA-82": // Avoid infinite loops
                    returnValue = 835; // Infinite Loop
                    break;
                case "MISRA2004-11_4": // "A cast should not be performed between a pointer to
                    // object type and a different pointer to object type
                    returnValue = 843; // Type Confusion
                    break;

                default:
                    System.err.println(
                            "WARNING: Parasoft-Unrecognized finding type: "
                                    + catToUse
                                    + " where original 'cat' is: '"
                                    + originalCategory
                                    + "' and rule origId (which might be null) is: '"
                                    + origId
                                    + "'");
                    foundCWEValue = false;
            }
            return returnValue; // If unmapped, returns -1
        } finally {
            if (foundCWEValue) {
                if (origId != null && (returnValue != parsedCWENumber)) {
                    return verifyCWEtoCWECategoryMappings(
                            returnValue, parsedCWENumber, originalCategory, origId);
                } // End if (origId != null && (returnValue != parsedCWENumber))
            } // End if (foundCWEValue)
            return returnValue; // Default if finally doesn't return anything.
        } // End finally {}
    }

    /**
     * This method verifies that the returnValue CWE maps to one of one of the expected mapped
     * categories for the CWE category for that rule. If not, it prints out a warning that it found
     * an unexpected mapping.
     *
     * @param returnValue The return value calculated by all the rule mappings.
     * @param parsedCWENumber The CWE parsed out of the rule 'category' for this rule, which may not
     *     match the provided returnValue.
     * @param originalCategory The original category name for this finding
     * @param origId The computed CWE from the original category name
     * @return The retunValue passed in.
     */
    private static int verifyCWEtoCWECategoryMappings(
            int returnValue, int parsedCWENumber, String originalCategory, String origId) {

        // This switch matches the return value against the parsedCWENumber from (e.g.,
        // CWE.79.VPPD) and filters out the 'known' mismatches we've reported to
        // Parasoft
        switch (returnValue) {
            case -1: // If unmapped, don't care.
            case 0: // If marked don't care, we don't care.
                return returnValue;
            case 15: // External Control of System or Config Setting
                // Jtest: 'CWE.20.UCO' for original rule ID: 'SERVLET.UCO'
                // Jtest: 'CWE.20.SYSP' for original rule ID: 'SECURITY.BV.SYSP'
                if (parsedCWENumber == 20) return returnValue;
                break;
            case 20: // Improper Input Validation (Discouraged)
                // 'CWE.79.VPPD' for original rule ID: 'BD.SECURITY.VPPD'
                // 'CWE.352.VPPD' for original rule ID: 'BD.SECURITY.VPPD'
                // 'CWE.829.TDFILES' for original rule ID: 'BD.SECURITY.TDFILES'
                // dotTEST has same mappings from original rule: SEC.VPPD
                // dotTEST: 'CWE.74.VPPD' for original rule ID: 'SEC.VPPD' (OnTheCUSP)
                // dotTEST: 'CWE.80.VPPD' for original rule ID: 'SEC.VPPD'
                // dotTEST: 'CWE.88.VPPD' for original rule ID: 'SEC.VPPD'
                if (parsedCWENumber == 74
                        || parsedCWENumber == 79
                        || parsedCWENumber == 80
                        || parsedCWENumber == 88
                        || parsedCWENumber == 352
                        || parsedCWENumber == 829) return returnValue;
                break;
            case 22: // Path Traversal
                // 'CWE.434.TDFNAMES' for original rule ID: 'BD.SECURITY.TDFNAMES'
                // 'CWE.829.TDFNAMES' for original rule ID: 'BD.SECURITY.TDFNAMES'
                // dotTEST: 'CWE.20.TDFNAMES' for original rule ID:
                // 'BD.SECURITY.TDFNAMES'
                // dotTEST: 'CWE.74.TDFNAMES' for original rule ID:
                // 'BD.SECURITY.TDFNAMES'
                // dotTEST: 'CWE.99.TDFNAMES' for original rule ID:
                // 'BD.SECURITY.TDFNAMES'
                // dotTEST: 'CWE.668.SCS0018' for original rule ID:
                // 'ROSLYN.SCS.INJ.SCS0018'
                // cppTEST: BD-SECURITY-TDFNAMES where original 'cat' is: 'CWE-20-i'
                // cppTEST: BD-SECURITY-TDFNAMES where original 'cat' is: 'CWE-23-a'
                // cppTEST: BD-SECURITY-TDFNAMES where original 'cat' is: 'CWE-36-a'
                if (parsedCWENumber == 20
                        || parsedCWENumber == 23
                        || parsedCWENumber == 36
                        || parsedCWENumber == 74
                        || parsedCWENumber == 99
                        || parsedCWENumber == 434
                        || parsedCWENumber == 668
                        || parsedCWENumber == 829) return returnValue;
                break;
            case 77: // Command Injection
                // SECURITY.WSC.APIBS where original 'cat' is: 'CWE.20.APIBS'
                // dotTEST: 'CWE.74.TDCMD' for original rule ID: 'BD.SECURITY.TDCMD'
                // dotTEST: 'CWE.78.TDCMD' for original rule ID: 'BD.SECURITY.TDCMD'
                // dotTEST: 'CWE.88.TDCMD' for original rule ID: 'BD.SECURITY.TDCMD'
                // cppTEST: BD-SECURITY-TDCMD where original 'cat' is: 'CWE-20-d'
                // cppTEST: BD-SECURITY-TDCMD where original 'cat' is: 'CWE-78-a'
                if (parsedCWENumber == 20
                        || parsedCWENumber == 74
                        || parsedCWENumber == 78
                        || parsedCWENumber == 88) return returnValue;
                break;
            case 79: // XSS
                // 'CWE.352.TDXSS' for original rule ID: 'BD.SECURITY.TDXSS'
                // dotTEST: 'CWE.20.TDXSS' for original rule ID: 'BD.SECURITY.TDXSS'
                // dotTEST: 'CWE.74.TDXSS' for original rule ID: 'BD.SECURITY.TDXSS'
                // The above is simply the WRONG mapping
                if (parsedCWENumber == 20 || parsedCWENumber == 74 || parsedCWENumber == 352)
                    return returnValue;
                break;
            case 89: // SQLi Injection
                // JTest: SECURITY.IBA.UPS where original 'cat' is: 'CWE.74.UPS'
                // dotTEST: BD.SECURITY.TDSQLC where original 'cat' is: 'CWE.20.TDSQLC'
                // dotTEST: 'CWE.74.TDSQLC' for original rule ID: 'BD.SECURITY.TDSQLC'
                // The above is simply the WRONG mapping
                if (parsedCWENumber == 20 || parsedCWENumber == 74) return returnValue;
                break;
            case 90: // LDAP Injection
                // dotTEST: 'CWE.74.TDLDAP' for original rule ID: 'BD.SECURITY.TDLDAP'
                // dotTEST: ROSLYN.SCS.INJ.SCS0031 where original 'cat' is:
                // 'CWE.74.SCS0031'
                // The above is too generic (i.e., just injection)
                if (parsedCWENumber == 74) return returnValue;
                break;
            case 94: // Code Injection
                // dotTEST: 'CWE.74.TDCODE' for original rule ID: 'BD.SECURITY.TDCODE'
                // The above is too generic (i.e., just injection)
                // dotTEST: 'CWE.95.TDCODE' for original rule ID: 'BD.SECURITY.TDCODE'
                if (parsedCWENumber == 74 || parsedCWENumber == 95) return returnValue;
                break;
            case 99: // Resource Injection
                // dotTEST: 'CWE.20.TDNET' for original rule ID: 'BD.SECURITY.TDNET'
                // dotTEST: 'CWE.74.TDNET' for original rule ID: 'BD.SECURITY.TDNET'
                // dotTEST: 'CWE.601.TDNET' for original rule ID: 'BD.SECURITY.TDNET'
                // dotTEST: 'CWE.918.TDNET' for original rule ID: 'BD.SECURITY.TDNET'
                if (parsedCWENumber == 20
                        || parsedCWENumber == 74
                        || parsedCWENumber == 601
                        || parsedCWENumber == 918) return returnValue;
                break;
            case 111: // Direct Use of Unsafe JNI
                // Jtest: PORT.NATV where original 'cat' is: 'CWE.20.NATV'
                // Jtest: SECURITY.IBA.NATIW where original 'cat' is: 'CWE.20.NATIW'
                if (parsedCWENumber == 20) return returnValue;
                break;
            case 113: // HTTP Request/Response Splitting
                // 'CWE.20.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                // 'CWE.79.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                // Jtest: 'CWE.644.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                // 'CWE.352.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                // dotTEST: 'CWE.74.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                // dotTEST: 'CWE.80.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                // dotTEST: 'CWE.601.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                if (parsedCWENumber == 20
                        || parsedCWENumber == 74
                        || parsedCWENumber == 79
                        || parsedCWENumber == 80
                        || parsedCWENumber == 352
                        || parsedCWENumber == 601
                        || parsedCWENumber == 644) return returnValue;
                break;
            case 119: // Improper Restrictions of Ops within Bounds of Memory Buffer
                // cppTEST: BD-PB-ARRAY where original 'cat' is: 'CWE-121-a'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-121-f'
                // cppTEST: BD-SECURITY-OVERFRD where original 'cat' is: 'CWE-121-h'
                // cppTEST: CODSTA-143 where original 'cat' is: 'CWE-121-j'
                // cppTEST: BD-PB-ARRAY where original 'cat' is: 'CWE-122-a'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-122-f'
                // cppTEST: BD-SECURITY-OVERFRD where original 'cat' is: 'CWE-122-h'
                // cppTEST: CODSTA-143 where original 'cat' is: 'CWE-122-j'
                // cppTEST: BD-PB-ARRAY where original 'cat' is: 'CWE-124-a'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-124-e'
                // cppTEST: CODSTA-143 where original 'cat' is: 'CWE-124-h'
                // cppTEST: BD-PB-ARRAY where original 'cat' is: 'CWE-125-a'
                // cppTEST: BD-PB-ARRAY where original 'cat' is: 'CWE-126-a'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-126-e'
                // cppTEST: BD-SECURITY-OVERFRD where original 'cat' is: 'CWE-126-f'
                // cppTEST: CODSTA-143 where original 'cat' is: 'CWE-126-g'
                // cppTEST: BD-PB-ARRAY where original 'cat' is: 'CWE-127-a'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-127-e'
                // cppTEST: BD-SECURITY-OVERFRD where original 'cat' is: 'CWE-127-f'
                // cppTEST: CODSTA-143 where original 'cat' is: 'CWE-127-g'
                // cppTEST: BD-PB-ARRAY where original 'cat' is: 'CWE-787-a'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-20-a'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-125-e'
                // cppTEST: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-787-h'
                if (parsedCWENumber == 20
                        || parsedCWENumber == 121
                        || parsedCWENumber == 122
                        || parsedCWENumber == 124
                        || parsedCWENumber == 125
                        || parsedCWENumber == 126
                        || parsedCWENumber == 127
                        || parsedCWENumber == 787) return returnValue;
                break;
            case 125: // Out-of-bounds Read
                // cppTEST: BD-SECURITY-OVERFRD where original 'cat' is: 'CWE-119-h'
                // cppTEST: BD-PB-OVERFRD where original 'cat' is: 'CWE-119-d'
                // cppTEST: BD-PB-OVERFRD where original 'cat' is: 'CWE-121-d'
                // cppTEST: BD-PB-OVERFRD where original 'cat' is: 'CWE-122-d'
                // cppTEST: BD-PB-OVERFRD where original 'cat' is: 'CWE-126-d'
                // cppTEST: BD-PB-OVERFRD where original 'cat' is: 'CWE-127-d'
                // cppTEST: BD-PB-OVERFNZT where original 'cat' is: 'CWE-665-a'
                if (parsedCWENumber == 119
                        || parsedCWENumber == 121
                        || parsedCWENumber == 122
                        || parsedCWENumber == 126
                        || parsedCWENumber == 127
                        || parsedCWENumber == 665) return returnValue;
                break;
            case 129: // Improper Validation of Array Index
                // Jtest: PB.RE.CAI where original 'cat' is: 'CWE.20.CAI'
                // Seems like above is in the wrong CWE
                // Jtest: category 'CWE.20.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                // Jtest: category 'CWE.119.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                // Jtest: category 'CWE.125.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                // Jtest: category 'CWE.787.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                if (parsedCWENumber == 20
                        || parsedCWENumber == 119
                        || parsedCWENumber == 125
                        || parsedCWENumber == 787) return returnValue;
                break;
            case 134: // Use of Externally-Controlled Format String
                // Jtest: BD.SECURITY.TDINPUT where original 'cat' is: 'CWE.20.TDINPUT'
                // cppTEST: BD-SECURITY-TDINPUT where original 'cat' is: 'CWE-20-g'
                // dotTEST: 'CWE.668.TDINPUT' for original rule ID:
                // 'BD.SECURITY.TDINPUT'
                // The above are simply the WRONG mappings
                if (parsedCWENumber == 20 || parsedCWENumber == 668) return returnValue;
                break;
            case 190: // Integer Overflow or Wraparound
                // BD.PB.INTWRAP where original 'cat' is: 'CWE.20.INTWRAP'
                // dotTEST: 'CWE.191.INTWRAP' for original rule ID: 'BD.PB.INTWRAP' (All
                // CWEs)
                // cppTEST: BD-SECURITY-TDINTOVERF where original 'cat' is: 'CWE-20-b'
                // cppTEST: BD-SECURITY-TDINTOVERF where original 'cat' is: 'CWE-195-1'
                if (parsedCWENumber == 20 || parsedCWENumber == 191 || parsedCWENumber == 195)
                    return returnValue;
                break;
            case 195: // Signed to Unsigned Conversion Error
                // cppTEST: BD-API-NEGPARAM where original 'cat' is: 'CWE-194-b'
                if (parsedCWENumber == 194) return returnValue;
                break;
            case 197: // Numeric Truncation Error
                // dotTEST: BD.PB.INTDL where original cat is'CWE.681.INTDL'
                if (parsedCWENumber == 681) return returnValue;
                break;
            case 200: // Exposure of Sensitive Info to Unauthorized Actor
                // 'CWE.502.SSSD' for original rule ID: 'BD.SECURITY.SSSD'
                // Jtest:  'CWE.497.SENS' for original rule ID: 'BD.SECURITY.SENS'
                // dotTEST: 'CWE.209.SENS' for original rule ID: 'BD.SECURITY.SENS'
                // dotTEST: 'CWE.668.SENS' for original rule ID: 'BD.SECURITY.SENS'
                // cppTEST: BD-SECURITY-TDCONSOLE where original 'cat' is: 'CWE-20-e'
                // The above seems like the WRONG mappings
                if (parsedCWENumber == 20
                        || parsedCWENumber == 209
                        || parsedCWENumber == 497
                        || parsedCWENumber == 502
                        || parsedCWENumber == 668) return returnValue;
                break;
            case 209: // Generation of Error Message Containing Sensitive Info
                // SECURITY.ESD.PEO: "Do not include exception messages in output"
                // Jtest: 'CWE.200.PEO' for original rule ID: 'SECURITY.ESD.PEO'
                // Jtest: 'CWE.497.PEO' for original rule ID: 'SECURITY.ESD.PEO'
                // Jtest: 'CWE.668.PEO' for original rule ID: 'SECURITY.ESD.PEO'
                // This seems like a more specific mapping for this issue
                if (parsedCWENumber == 200 || parsedCWENumber == 497 || parsedCWENumber == 668)
                    return returnValue;
                break;
            case 256: // Plaintext Storage of a Password
                // BD.SECURITY.TDPASSWD where original 'cat' is: 'CWE.287.TDPASSWD'
                // The above seems like the WRONG mapping
                // dotTEST: 'CWE.522.TDPASSWD' for original rule ID:
                // 'BD.SECURITY.TDPASSWD'
                // dotTEST: 'CWE.668.TDPASSWD' for original rule ID:
                // 'BD.SECURITY.TDPASSWD'
                if (parsedCWENumber == 287 || parsedCWENumber == 522 || parsedCWENumber == 668)
                    return returnValue;
                break;
            case 259: // Use of Hard-Coded Password
                // SECURITY.WSC.HCCS where original 'cat' is: 'CWE.287.HCCS'
                // SECURITY.WSC.HCCS where original 'cat' is: 'CWE.798.HCCS'
                // Above seem like the wrong mapping. Should be more specific like this.
                // dotTEST: ROSLYN.SCS.PWM.SCS0015 original 'cat' is: 'CWE.798.SCS0015'
                if (parsedCWENumber == 287 || parsedCWENumber == 798) return returnValue;
                break;
            case 290: // Authentication Bypass by Spoofing
                // SECURITY.WSC.HTTPRHA where original 'cat' is: 'CWE.287.HTTPRHA'
                if (parsedCWENumber == 287) return returnValue;
                break;
            case 295: // Improper Certificate Validation
                // SECURITY.WSC.VSI where original 'cat' is: 'CWE.297.VSI'
                if (parsedCWENumber == 297) return returnValue;
                break;
            case 306: // Missing Authentication for Critical Function
                // SECURITY.WSC.SSM where original 'cat' is: 'CWE.287.SSM'
                if (parsedCWENumber == 287) return returnValue;
                break;
            case 319: // Cleartext Transmission of Sensitive Information
                // SECURITY.WSC.USC where original 'cat' is: 'CWE.287.USC'
                // 'CWE.319.USC' for original rule ID: 'SECURITY.WSC.USC'
                // 'CWE.522.USC' for original rule ID: 'SECURITY.WSC.USC'
                // 'CWE.523.USC' for original rule ID: 'SECURITY.WSC.USC'
                // 'CWE.668.USC' for original rule ID: 'SECURITY.WSC.USC'
                if (parsedCWENumber == 287
                        || parsedCWENumber == 311
                        || parsedCWENumber == 522
                        || parsedCWENumber == 523
                        || parsedCWENumber == 668) return returnValue;
                break;
            case 321: // Use of Hard-Coded Cryptographic Key
                // SECURITY.WSC.HCCK where original 'cat' is: 'CWE.287.HCCK'
                // SECURITY.WSC.HCCK where original 'cat' is: 'CWE.798.HCCK'
                // dotTEST: ROSLYN.MSNA.SECURITY.CA5390 original 'cat' is:
                // 'CWE.287.CA5390'
                // Above seem like the wrong mapping. Should be more specific like this.
                if (parsedCWENumber == 287 || parsedCWENumber == 798) return returnValue;
                break;
            case 330: // Weak Random
                // Jtest: 'CWE.338.SRD' for original rule ID: 'SECURITY.WSC.SRD'
                if (parsedCWENumber == 338) return returnValue;
                break;
            case 336: // Same Seed in PRNG
                // Jtest: SECURITY.WSC.ENPP where original 'cat' is: 'CWE.337.ENPP'
                if (parsedCWENumber == 337) return returnValue;
                break;
            case 350: // Reliance on Reverse DNS Resolution for Security-Critical Action
                // SECURITY.WSC.DNSL where original 'cat' is: 'CWE.287.DNSL'
                // dotTEST: SEC.WEB.IIPHEU where original 'cat' is: 'CWE.287.IIPHEU'
                // The above is simply the WRONG mapping
                if (parsedCWENumber == 287) return returnValue;
                break;
            case 352: // CSRF
                // Jtest:  'CWE.807.UOSC' for original rule ID: 'SECURITY.WSC.UOSC'
                if (parsedCWENumber == 807) return returnValue;
                break;
            case 362: // Race Condition
                // dotTEST: 'CWE.662.DIFCS' for original rule ID: 'BD.TRS.DIFCS'
                if (parsedCWENumber == 662) return returnValue;
                break;
            case 377: // Insecure Temp File
                // Jtest: SECURITY.IBA.ATF where original 'cat' is: 'CWE.668.ATF'
                if (parsedCWENumber == 668) return returnValue;
                break;
            case 383: // J2EE Bad Practice: Direct Use of Threads
                // TRS.ISTART where original 'cat' is: 'CWE.400.ISTART'
                // 'CWE.770.ISTART' for original rule ID: 'TRS.ISTART'
                // The above is simply the WRONG mapping
                if (parsedCWENumber == 400 || parsedCWENumber == 770) return returnValue;
                break;
            case 395: // Use of NPE Catch to Detect Null Pointer Dereference
                // 'CWE.476.NP' for original rule ID: 'BD.EXCEPT.NP'
                // 476 is Null Pointer Dereference
                if (parsedCWENumber == 476) return returnValue;
                break;
            case 400: // Uncontrolled Resource Consumption
                // Jtest: 'CWE.459.LEAKS' for original rule ID: 'BD.RES.LEAKS'
                // dotTEST: 'CWE.771.LEAKS' for original rule ID: 'BD.RES.LEAKS'
                // dotTEST: 'CWE.772.LEAKS' for original rule ID: 'BD.RES.LEAKS'
                if (parsedCWENumber == 459 || parsedCWENumber == 771 || parsedCWENumber == 772)
                    return returnValue;
                break;
            case 404: // Improper Resource Shutdown or Release
                // cppTEST: BD-RES-LEAKS where original 'cat' is: 'CWE-401-a'
                // cppTEST: BD-RES-LEAKS where original 'cat' is: 'CWE-459-a'
                // cppTEST: BD-RES-LEAKS where original 'cat' is: 'CWE-772-a'
                // cppTEST: BD-RES-LEAKS where original 'cat' is: 'CWE-773-a'
                // cppTEST: BD-RES-LEAKS where original 'cat' is: 'CWE-775-a'
                if (parsedCWENumber == 401
                        || parsedCWENumber == 459
                        || parsedCWENumber == 772
                        || parsedCWENumber == 773
                        || parsedCWENumber == 775) return returnValue;
                break;
            case 416: // Use After Free
                // cppTEST: 'CWE-415-a' for original rule ID: 'BD-RES-FREE'
                if (parsedCWENumber == 415) return returnValue;
                break;
            case 426: // Untrusted Search Path
                // dotTEST: SEC.PBRTE where original 'cat' is: 'CWE.668.PBRTE'
                // The above is too generic a mapping. Should be 426
                if (parsedCWENumber == 668) return returnValue;
                break;
            case 427: // Uncontrolled Search Path Element
                // cppTEST: BD-SECURITY-TDENV where original 'cat' is: 'CWE-20-f'
                if (parsedCWENumber == 20) return returnValue;
                break;
            case 457: // Use of Uninitialized Variable
                // cppTEST: BD-PB-NOTINIT where original 'cat' is: 'CWE-758-a'
                if (parsedCWENumber == 758) return returnValue;
                break;
            case 470: // Unsafe Reflection
                // BD.SECURITY.TDRFL where original 'cat' is: 'CWE.20.TDRFL'
                // The above is simply the WRONG mapping
                if (parsedCWENumber == 20) return returnValue;
                break;
            case 476: // Null Pointer Dereference
                // cppTEST: 'CWE-690-a' for original rule ID: 'BD-PB-NP'
                if (parsedCWENumber == 690) return returnValue;
                break;
            case 491: // Public cloneable() Method without Final (Object Hijack)
                // Jtest: SECURITY.WSC.CLONE where original 'cat' is: 'CWE.668.CLONE'
                // Jtest: SECURITY.WSC.MCNC where original 'cat' is: 'CWE.668.MCNC'
                if (parsedCWENumber == 668) return returnValue;
                break;
            case 492: // Make all member classes 'private'
                // Jtest: SECURITY.WSC.INNER where original 'cat' is: 'CWE.668.INNER'
                if (parsedCWENumber == 668) return returnValue;
                break;
            case 499: // Serializable Class Containing Sensitive Data
                // Jtest: SECURITY.ESD.SIF where original 'cat' is: 'CWE.668.SIF'
                // Jtest: SECURITY.WSC.SER where original 'cat' is: 'CWE.668.SER'
                if (parsedCWENumber == 668) return returnValue;
                break;
            case 500: // Public Static Field Not Marked Final
                // Jtest: SECURITY.EAB.SPFF where original 'cat' is: 'CWE.668.SPFF'
                if (parsedCWENumber == 668) return returnValue;
                break;
            case 532: // Insertion of Sensitive Info into Log File
                // BD.SECURITY.TDLOG where original 'cat' is: 'CWE.20.TDLOG'
                // The above seems like the WRONG mapping
                // Jtest: SECURITY.ESD.CONSEN where original 'cat' is: 'CWE.200.CONSEN'
                // Jtest: SECURITY.ESD.CONSEN where original 'cat' is: 'CWE.213.CONSEN'
                // Jtest: SECURITY.ESD.CONSEN where original 'cat' is: 'CWE.359.CONSEN'
                // Jtest: SECURITY.ESD.CONSEN where original 'cat' is: 'CWE.668.CONSEN'
                if (parsedCWENumber == 20
                        || parsedCWENumber == 200
                        || parsedCWENumber == 213
                        || parsedCWENumber == 359
                        || parsedCWENumber == 668) return returnValue;
                break;
            case 561: // Dead Code
                // JTest: 'CWE.570.UCIF' for original rule ID: 'UC.UCIF'
                // JTest: 'CWE.571.UCIF' for original rule ID: 'UC.UCIF'
                // dotTEST: 'CWE.705.ANIL' for original rule ID: 'CS.PB.ANIL'
                // dotTEST: 'CWE.1069.EEB' for original rule ID: 'CS.PB.EEB'
                // dotTEST: 'CWE.1071.BEB' for original rule ID: 'CS.BRM.BEB'
                // dotTEST: 'CWE.1071.CEB' for original rule ID: 'CS.PB.CEB'
                // dotTEST: 'CWE.1071.ITEB' for original rule ID: 'CS.PB.IEB''
                // cppTEST: OPT-22 where original 'cat' is: 'CWE-398-b'
                // cppTEST: OPT-32_b where original 'cat' is: 'CWE-398-c'
                // cppTEST: OPT-35 where original 'cat' is: 'CWE-398-d'
                // cppTEST: OPT-49 where original 'cat' is: 'CWE-398-e'
                // cppTEST: OPT-50 where original 'cat' is: 'CWE-398-f'
                // OPT-22 thru OPT-50 seem like they should be dead code, not code
                // quality
                // cppTEST: OPT-51 where original 'cat' is: 'CWE-390-b'
                if (parsedCWENumber == 390
                        || parsedCWENumber == 398
                        || parsedCWENumber == 570
                        || parsedCWENumber == 571
                        || parsedCWENumber == 705
                        || parsedCWENumber == 1069
                        || parsedCWENumber == 1071) return returnValue;
                break;
            case 569: // Expression Issues (usually always false (570) or always true
                // (571)
                // JTest: 'CWE.561.CC' for original rule ID: 'BD.PB.CC'
                // dotTEST: 'CWE.570.CC' for original rule ID: 'BD.PB.CC'
                // dotTEST: 'CWE.571.CC' for original rule ID: 'BD.PB.CC'
                // cppTEST: BD-PB-CC where original 'cat' is: 'CWE-570-a'
                // cppTEST: BD-PB-CC where original 'cat' is: 'CWE-571-a'
                if (parsedCWENumber == 561 || parsedCWENumber == 570 || parsedCWENumber == 571)
                    return returnValue;
                break;
            case 582: // Array Declared Public, Final, and Static
                // Jtest: PB.CUB.IMM where original 'cat' is: 'CWE.607.IMM'
                // Jtest: PB.CUB.IMM where original 'cat' is: 'CWE.668.IMM'
                // Jtest: PB.CUB.PSFA where original 'cat' is: 'CWE.668.PSFA'
                if (parsedCWENumber == 607 || parsedCWENumber == 668) return returnValue;
                break;
            case 597: // Use of Wrong Operator in String Comparison
                // Jtest: PB.CUB.UEIC where original 'cat' is: 'CWE.595.UEIC'
                if (parsedCWENumber == 595) return returnValue;
                break;
            case 601: // Open Redirect
                // JTest: 'CWE.601.UCO' for original rule ID: 'SERVLET.UCO'
                if (parsedCWENumber == 20) return returnValue;
                break;
            case 605: // Multiple Binds to the Same Port
                // JTest: PORT.HCNA where original 'cat' is: 'CWE.1051.HCNA'
                if (parsedCWENumber == 1051) return returnValue;
                break;
            case 606: // Unchecked Input for Loop Condition
                // cppTEST: BD-SECURITY-TDLOOP where original 'cat' is: 'CWE-400-b'
                // cppTEST: 'CWE-20-j' for original rule ID: 'SECURITY-38'
                if (parsedCWENumber == 20 || parsedCWENumber == 400) return returnValue;
                break;
            case 609: // Double-Checked Locking
                // JTest: TRS.DCL where original 'cat' is: 'CWE.362.DCL'
                if (parsedCWENumber == 362) return returnValue;
                break;
            case 643: // XPath Injection
                // Jtest: SECURITY.IBA.XPIJ where original 'cat' is: 'CWE.652.XPIJ'
                // Jtest: BD.SECURITY.TDXPATH where original 'cat' is: 'CWE.652.TDXPATH'
                // Above is WRONG mapping to XQuery injection, which it should be to XPath Injection
                // Jtest: BD.SECURITY.TDXPATH where original 'cat' is: 'CWE.829.TDXPATH'
                // Jtest: SECURITY.IBA.XPIJ where original 'cat' is: 'CWE.74.XPIJ'
                // dotTEST: ROSLYN.SCS.INJ.SCS0003 for original 'cat' is: 'CWE.74.SCS0003'
                // The above is too generic a mapping. Should be 643
                if (parsedCWENumber == 74 || parsedCWENumber == 652 || parsedCWENumber == 829)
                    return returnValue;
                break;
            case 675: // Multiple Operations on Resource in Single-Operational Context
                // dotTEST: 'CWE.416.DISP' for original rule ID: 'BD.PB.DISP'
                if (parsedCWENumber == 416) return returnValue;
                break;
            case 703: // Improper Check or Handling of Exceptional Conditions
                // dotTEST: 'CWE.391.LGE' for original rule ID: 'SEC.LGE'
                if (parsedCWENumber == 391) return returnValue;
                break;
            case 732: // Incorrect Permission Assignment for Critical Resource
                // Jtest: SECURITY.WSC.ASNF where original 'cat' is: 'CWE.276.ASNF'
                // Jtest: SECURITY.WSC.ASNF where original 'cat' is: 'CWE.668.ASNF'
                // Jtest: SECURITY.WSC.IDP where original 'cat' is: 'CWE.279.IDP'
                // Jtest: SECURITY.WSC.IDP where original 'cat' is: 'CWE.668.IDP'
                if (parsedCWENumber == 276 || parsedCWENumber == 279 || parsedCWENumber == 668)
                    return returnValue;
                break;
            case 759: // Use of a One-Way Hash w/Out a Salt
                // Jtest: SECURITY.WSC.MDSALT where original 'cat' is: 'CWE.328.MDSALT'
                if (parsedCWENumber == 328) return returnValue;
                break;
            case 761: // Free of Pointer not at Start of Buffer
                // cppTEST: BD-RES-INVFREE where original 'cat' is: 'CWE-590-a'
                if (parsedCWENumber == 590) return returnValue;
                break;
            case 764: // Multiple Locks of a Critical Resource
                // Jtest: BD.TRS.LOCK where original 'cat' is: 'CWE.667.LOCK'
                if (parsedCWENumber == 667) return returnValue;
                break;
            case 770: // Allocation of Resources w/Out Limits or Throttling
                // cppTEST:  'CWE-789-a' for original rule ID: 'BD-SECURITY-TDALLOC'
                if (parsedCWENumber == 789) return returnValue;
                break;
            case 787: // Out-of-bounds Write
                // cppTEST: BD-PB-OVERFWR where original 'cat' is: 'CWE-119-e'
                // cppTEST: BD-SECURITY-OVERFWR where original 'cat' is: 'CWE-119-i'
                // cppTEST: BD-PB-PATHBUF where original 'cat' is: 'CWE-119-k'
                // cppTEST: BD-PB-OVERFWR where original 'cat' is: 'CWE-121-e'
                // cppTEST: BD-SECURITY-OVERFWR where original 'cat' is: 'CWE-121-i'
                // cppTEST: BD-PB-PATHBUF where original 'cat' is: 'CWE-121-k'
                // cppTEST: BD-PB-OVERFWR where original 'cat' is: 'CWE-122-e'
                // cppTEST: BD-SECURITY-OVERFWR where original 'cat' is: 'CWE-122-i'
                // cppTEST: BD-PB-PATHBUF where original 'cat' is: 'CWE-122-k'
                // cppTEST: BD-PB-OVERFWR where original 'cat' is: 'CWE-124-d'
                // cppTEST: BD-SECURITY-OVERFWR where original 'cat' is: 'CWE-124-g'
                // cppTEST: BD-PB-PATHBUF where original 'cat' is: 'CWE-124-i'
                if (parsedCWENumber == 119
                        || parsedCWENumber == 121
                        || parsedCWENumber == 122
                        || parsedCWENumber == 124) return returnValue;
                break;
            case 806: // Buffer Access Using Size of Source Buffer
                // Jtest: SECURITY.WSC.BUSSB where original 'cat' is: 'CWE.20.BUSSB'
                // Jtest: SECURITY.WSC.BUSSB where original 'cat' is: 'CWE.119.BUSSB'
                if (parsedCWENumber == 20 || parsedCWENumber == 119) return returnValue;
                break;
            case 838: // Inappropriate Encoding for Output Context
                // Jtest: INTER.SEO where original 'cat' is: 'CWE.173.SEO'
                if (parsedCWENumber == 173) return returnValue;
                break;
            case 1004: // Missing HttpOnly on Sensitive Cookies
                // Jtest: SECURITY.WSC.SCHTTP where original 'cat' is: 'CWE.668.SCHTTP'
                // Jtest: SECURITY.WSC.SCHTTP where original 'cat' is: 'CWE.732.SCHTTP'
                // dotTEST: ROSLYN.MSNA.SECURITY.CA5396 where original 'cat' is:
                // 'CWE.668.CA5396'
                // dotTEST: ROSLYN.MSNA.SECURITY.CA5396 where original 'cat' is:
                // 'CWE.732.CA5396' and rule origId (which might be null) is:
                // 'ROSLYN.MSNA.SECURITY.CA5396'
                if (parsedCWENumber == 668 || parsedCWENumber == 732) return returnValue;
                break;
            case 1235: // Incorrect Use of Autoboxing for Performance Crit Ops
                // Jtest: 'CWE.400.ABUB' for original rule ID: 'CODSTA.READ.ABUB'
                if (parsedCWENumber == 400) return returnValue;
                break;
        } // End switch
        System.err.println(
                "WARNING: computed cweVal of: "
                        + returnValue
                        + " does not match CWE # from CWE category: '"
                        + originalCategory
                        + "' for original rule ID: '"
                        + origId
                        + "'");
        return returnValue; // Default if not returned earlier
    }
}
