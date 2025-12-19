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
            TestCaseResult tcr = parseStdViol(flaw, rulesList);
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        for (Node flaw : flowList) {
            TestCaseResult tcr = parseFlowViol(flaw, rulesList);
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
        int parsedCWENumber = -1; // Reset it to -1 every time this method is called.
        try {
            /* Rules can look like this:
            <Rule analyzer="com.parasoft.jtest.flowanalyzer" authTot="2125;" authUrg="9;" cat="CWE.79" desc="Protect against HTTP response splitting" id="CWE.79.TDRESP" origId="BD.SECURITY.TDRESP" sev="1" total="2125"/>
            */

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

            // This branch should
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

            // Use the actual rule name to look up the CWE # and return that value.
            switch (catToUse) {
                    // Jtest Java rule mappings:
                case "BD.SECURITY.TDCMD": // Protect against Command injection
                case "SECURITY.WSC.APIBS": // Prevent scripting API from executing untrusted code
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
                    returnValue = CweNumber.WEAK_RANDOM;
                    break;

                case "BD.SECURITY.EACM": // Encapsulate arguments of dangerous methods with a
                    // validation method
                case "BD.SECURITY.TDFILES": // Protect against File contents injection
                case "BD.SECURITY.VPPD": // Validate all dangerous data
                    // These are per Parasoft's CWE mapping
                case "SECURITY.BV.SYSP": // Do not access or set System properties
                case "SERVLET.UCO": // Use a Context Object to manage HTTP request parameters
                    returnValue = 20; // Input validation
                    break;

                case "BD.SECURITY.TDXML":
                    returnValue = 91; // XML Injection
                    break;
                case "BD.SECURITY.TDNET":
                    returnValue = 99; // Resource Injection
                    break;
                case "BD.SECURITY.XMLVAL":
                    returnValue = 112; // Missing XML Validation
                    break;
                case "BD.PB.ARRAY": // Avoid accessing arrays out of bounds
                    // case "BD.PB.ARRAYINP": // Avoid accessing arrays out of bounds - TODO:in
                    // previous study
                case "BD.SECURITY.ARRAY": // NOT Documented, but assuming its equivalent to above
                case "PB.RE.CAI": // Always check parameters before use in array access
                    returnValue = 129; // Improper Validation of Array Index
                    break;
                case "BD.SECURITY.TDINPUT": // Exclude unsanitized user input from format strings
                    returnValue = 134; // Use of Externally-Controlled Format String
                    break;
                case "BD.PB.INTWRAP":
                    returnValue = 190; // Integer Overflow or Wraparound
                    break;

                case "BD.SECURITY.SENS": // Prevent exposure of sensitive data
                case "BD.SECURITY.SSSD": // Safely serialize sensitive data
                case "SECURITY.ESD": // A category not a specific rule. Was used by older versions
                case "SECURITY.ESD.PEO": // Do not include exception messages in output
                case "SECURITY.ESD.SIO": // Avoid calling print methods System.err or System.out
                case "SECURITY.WSC.ACPST": // Do not call printStackTrace() on Throwable objects
                    returnValue = 200; // Exposure of Sensitive Data
                    break;
                case "BD.SECURITY.TDPASSWD": // Protect against using unprotected credentials
                    returnValue = 256; // Plaintext Storage of a Password
                    break;
                case "SECURITY.WSC.HCCS": // Avoid passing hardcoded usernames/passwords/URLs to
                    // database connection methods (Parasoft maps to CWE-798: Hard-coded Creds)
                    returnValue = 259; // Use of Hard-coded Password
                    break;
                case "SECURITY.WSC.VSI": // Properly validate server identity
                    returnValue = 287; // Improper Authentication
                    break;
                case "SECURITY.WSC.SSM": // Ensure that an appropriate security manager is set (They
                    // also map this to 287, which is another AuthN related
                    // CWE)
                    returnValue = 306; // Missing Authentication for Critical Function
                    break;
                case "SECURITY.WSC": // A category not a specific rule. Was used by older versions
                case "SECURITY.WSC.USC":
                    returnValue = 311; // Failure to encrypt sensitive data
                    break;
                case "SECURITY.WSC.HCCK": // Avoid using hard-coded cryptographic keys
                    returnValue = 321; // Use of Hard-coded Cryptographic Key
                    break;
                case "SECURITY.WSC.DNSL": // Avoid DNS Lookups for decision making
                    returnValue = 350; // Reliance on Reverse DNS for Security-Critical Action
                    break;
                case "SECURITY.WSC.UOSC": // Use getSecure()/setSecure() to enforce use of secure
                    // cookies
                    returnValue = 352; // CWE-352: CSRF
                    break;
                case "TRS.ISTART": // Do not call the 'start()' method directly on Thread class
                    // instances
                    returnValue = 383; // CWE-383: J2EE Bad Practice: Direct Use of Threads
                    break;
                case "BD.EXCEPT.NP":
                    returnValue = 395; // Don't catch NullPointerException
                    break;
                case "BD.EXCEPT.AN": // Avoid catching generic Exception/Throwable
                    returnValue = 396; // CWE-396: Declaration of Catch for Generic Exception
                    break;

                case "BD.RES.LEAKS": // Ensure resources are deallocated
                case "CODSTA.READ.ABUB": // Do not rely on automatic boxing/unboxing of primitive
                    // types (The vendor maps this to 400, not sure its right)
                case "TRS.UWNA": // Use wait() and notifyAll() instead of polling loops
                    returnValue = 400; // Uncontrolled Resource Consumption
                    break;
                case "TRS.RLF": // Release Locks in a 'finally' block
                    returnValue = 404; // Improper resource shutdown or release
                    break;
                case "BD.EXCEPT.NR": // Avoid NullReferenceException
                    returnValue = 476; // CWE-476: Null Pointer Dereference
                    break;
                case "PB.PDS": // Provide 'default:' for each 'switch' statement
                    returnValue =
                            478; // CWE-478: Missing Default Case in Multiple Condition Expression
                    break;
                case "PB.TYPO.ASI": // Avoid assignment within a condition
                    returnValue = 481; // CWE-481: Assigning instead of Comparing
                    break;
                case "PB.CUB.EBI": // Avoid erroneously placing statements outside of blocks
                    returnValue = 483; // Incorrect Block Delimitation
                    break;
                case "PB.TYPO.DAV": // Avoid assigning same variable in the fall-through switch case
                    // (TEST TODO: Maybe this should be 484:Omitted Break Statement in Switch"?
                    returnValue = 484; // Omitted Break Statement in Switch
                    break;
                case "BD.SECURITY.TDRFL": // Protect against Reflection injection
                    returnValue = 470; // Unsafe Reflection
                    break;
                case "SERIAL.VOBD": // Validate objects before deserialization
                    returnValue = 502; // Deserialization of Untrusted Data
                    break;
                case "BD.SECURITY.TDLOG": // Avoid passing unvalidated binary data to log methods
                case "SECURITY.ESD.CONSEN": // Do not log confidential or sensitive info
                    returnValue = 532; // Insertion of Sensitive Info into Log File
                    break;

                case "PB.USC.AES": // Avoid empty statements
                case "PB.USC.SAFL": // Avoid assignments/initializations to fields and/or local
                    // variables
                case "PB.USC.UIF": // Avoid unreachable 'else if' and 'else' cases
                case "UC.AURV": // Avoid local variables that are never read
                case "UC.EF": // Avoid empty finalize() methods
                case "UC.UCIF": // Avoid unnecessary 'if' statements
                    returnValue = 561; // CWE-561: Dead Code
                    break;

                case "BD.PB.VOVR":
                    returnValue = 563; // Variable assigned but not used
                    break;
                case "GC.FCF": // Call super.finalize() from finalize()
                case "GC.IFF": // Call super.finalize() in the finally block of finalize() methods
                    returnValue = 568; // finalize() Method Without super.finalize()
                    break;
                case "BD.PB.CC":
                    returnValue =
                            569; // Should be more specific. Either always true or false 571/570
                    break;

                case "CODSTA.EPC.SCLONE": // Call super.clone() in all clone() methods
                    returnValue = 580; // clone() Method Without super.clone()
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
                case "PB.LOGIC.FLRC": // Avoid infinite recursive methods
                    returnValue = 674; // Uncontrolled Recursion
                    break;

                case "BD.TRS.DLOCK": // Avoid Double Locking
                case "BD.TRS.LOCK": // Do not abandon unreleased locks (TODO: Or Maybe 'don't
                    // care'??
                    returnValue = 764; // Multiple Locks of a Critical Resource
                    break;
                case "SECURITY.UEHL": // Insecure logging category
                    returnValue = 778; // Insufficient Logging
                    break;

                case "BD.TRS.ORDER": // Do not acquire locks in a different order
                case "BD.TRS.TSHL": // Do not use blocking methods while holding a lock
                case "TRS.CSFS": // Do not cause deadlocks by calling a synchronized method from a
                    // synchronized method
                case "TRS.TSHL": // Do not call Thread.sleep() while holding a lock
                    returnValue = 833; // CWE-833: Deadlock
                    break;

                case "BD.PB.PBIOS":
                    returnValue = 1322; // Blocking code in single-threaded, non-blocking context
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
                    // https://docs.parasoft.com/display/DOTTEST20242/.NET+Core+Supported+Rules -
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
                case "ROSLYN.SCS.INJ.SCS0031": // LDAP injection
                    returnValue = CweNumber.LDAP_INJECTION;
                    break;
                case "BD.SECURITY.TDSQLC": // Protect against SQL injection
                    returnValue = CweNumber.SQL_INJECTION;
                    break;
                case "ROSLYN.SCS.INJ.SCS0029": // desc=Cross-Site Scripting (XSS)
                    returnValue = CweNumber.XSS; // CWE-79: XSS
                    break;
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
                    returnValue = 327; // CWE-327: Use of Broken/Risky Cryptographic Algorithm
                    break;
                case "ROSLYN.SCS.CRPGH.SCS0006": // Weak hashing function
                    returnValue = 328; // CWE-328: Use of Weak Hash
                    break;
                case "ROSLYN.MSNA.SECURITY.CA5394": // Do not use insecure randomness
                case "ROSLYN.SCS.CRPGH.SCS0005": // Weak Random Number Generator
                case "SEC.USSCR": // Use System.Security.Cryptography.RandomNumberGenerator instead
                    // of System.Random
                    returnValue = 338; // CWE-338: Cryptographically Weak PRNG
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
                    returnValue = 476; // CWE-476: NULL Pointer Dereference
                    break;
                case "CS.PB.DEFSWITCH": // Provide 'default:' for each 'switch' statement
                    returnValue =
                            478; // CWE-478: Missing Default Case in Multiple Condition Expression
                    break;
                case "SEC.AUIC": // Avoid using public inner classes to prevent access from
                    // untrusted classes
                    returnValue = 492; // CWE-492: Use of Inner Class Containing Sensitive Data
                    break;
                case "SEC.IREC": // Do not execute external code without integrity check
                    returnValue = 494; // CWE-494: Download of Code Without Integrity Check
                    break;
                case "ROSLYN.MSNA.SECURITY.CA2300": // Do not use insecure deserializer
                    // BinaryFormatter
                    returnValue = 502; // CWE-502: Deserialization of Untrusted Data
                    break;
                case "BD.SECURITY.SENSLOG": // Avoid passing sensitive data to functions that write
                    // to log files
                    returnValue = 532; // CWE-532: Insertion of Sensitive Info into Log File
                    break;
                case "PB.II.TODO": // Ensure that comments do not contain task tags
                    returnValue = 546; // CWE-546: Suspicious Comment
                    break;

                case "CS.PB.ANIL": // Avoid non-iterable loops
                case "CS.PB.CEB": // Avoid conditional statements with empty bodies
                case "CS.PB.EEB": // Avoid try, catch, finally, and using stmts w/ empty bodies
                case "CS.PB.USC.CC": // Avoid Unreachable Code in condition
                case "CS.PB.USC.UC": // Avoid Unreachable Code
                    returnValue = 561; // CWE-561: Dead Code
                    break;

                case "SEC.ATA": // Do not use the Trace.Assert() method in production code
                    returnValue = 617; // CWE-617: Reachable Assertion
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
                    returnValue = 676; // CWE-676: Use of Potentially Dangerous Function
                    break;
                case "BD.PB.INTVC": // Avoid value change when converting between integer types
                case "CT.ECLTS": // Avoid explicit conversions between data types if the conversion
                    // may cause data loss or unexpected results
                    returnValue = 681; // CWE-681: Incorrect Conversion between Numeric Types
                    break;
                case "SEC.LGE": // Ensure all exceptions are logged or rethrown
                    returnValue = 703; // Improper Check or Handling of Exceptional Conditions
                    break;
                case "SEC.ADLL": // Inspect calls to dynamically load libraries
                    returnValue = 829; // Inclusion of Functionality from Untrusted Control Sphere
                    break;
                case "ROSLYN.MSNA.SECURITY.CA5396": // Set HttpOnly to true for HttpCookie
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
                case "BD-SECURITY-ENV": // Protect against environment injection
                    returnValue = CweNumber.TRUST_BOUNDARY_VIOLATION;
                    break;

                case "CODSTA-203": // Do not hard code string literals (Parasoft maps to CWE-798-a)
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
                case "BD-SECURITY-OVERFRD": // Avoid buffer read overflow from tainted data
                    returnValue = 125; // Out-of-bounds Read
                    break;
                case "BD-SECURITY-TDINPUT": // Exclude unsanitized user input from format strings
                    returnValue = 134; // Use of Externally-Controlled Format String
                    break;
                case "BD-PB-INTDL": // Avoid data loss when converting between integer types
                case "BD-PB-INTUB": // Avoid signed integer overflows
                case "BD-PB-INTWRAP": // Avoid wraparounds when performing arith integer operations
                case "BD-SECURITY-TDINTOVERF": // Avoid potential integer overflow/underflow
                case "MISRA-048_a": // Avoid possible int overflow in expressions where result is
                    // cast to a wider integer type
                    returnValue = 190; // Integer Overflow or Wraparound
                    break;
                case "BD-SECURITY-TDCONSOLE": // Avoid printing tainted data to output console
                case "SECURITY-15": // Do not print potentially sensitive info from an app error
                    // into exception messages
                    returnValue = 200; // Exposure of Sensitive Info to Unauthorized Actor
                    break;
                case "BD-RES-STACKLIM": // Don't create vars on stack above defined limits
                    returnValue = 400; // Uncontrolled Resource Consumption
                    break;
                case "BD-PB-WRAPESC": // Do not point to wrapped object that has been freed
                case "BD-RES-FREE": // Do not use resources that have been freed
                case "MRM-31": // Freed memory shouldn't be accessed under any circumstances
                    returnValue = 416; // Use After Free
                    break;
                case "BD-PB-NP": // Avoid Null Pointer Dereferencing
                    returnValue = 476; // Null Pointer Dereference
                    break;
                case "BD-SECURITY-TDENV": // Protect against environment injection
                    returnValue = 501; // Trust Boundary Violation
                    break;
                case "BD-SECURITY-TDLOOP": // Validate potentially tainted data before use in
                    // controlling expression of a loop
                case "SECURITY-38": // Untrusted data is used as a loop boundary
                    returnValue = 606; // Unchecked Input for Loop Condition
                    break;
                case "BD-SECURITY-OVERFWR": // Avoid buffer write overflow from tainted data
                case "BD-PB-OVERFWR": // Avoid overflow when writing to a buffer
                case "BD-PB-PATHBUF": // Ensure output buffer is large enough when using path
                    // manipulation functions
                    returnValue = 787; // Out-of-bounds Write
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
            }
            return returnValue; // If unmapped, returns -1
        } finally {
            if (origId != null && (returnValue != parsedCWENumber)) {

                // This switch matches the return value against the parsedCWENumber from (e.g.,
                // CWE.79.VPPD) and filters out the 'known' mismatches we've reported to Parasoft
                switch (returnValue) {
                    case -1: // If unmapped, don't care.
                    case 0: // If marked don't care, we don't care.
                        return returnValue;
                    case 20: // Improper Input Validation (Discouraged)
                        // 'CWE.79.VPPD' for original rule ID: 'BD.SECURITY.VPPD'
                        // 'CWE.352.VPPD' for original rule ID: 'BD.SECURITY.VPPD'
                        // dotTEST has same mappings from original rule: SEC.VPPD
                        // dotTEST: 'CWE.74.VPPD' for original rule ID: 'SEC.VPPD' (OnTheCUSP)
                        // dotTEST: 'CWE.80.VPPD' for original rule ID: 'SEC.VPPD' (All CWEs)
                        // dotTEST: 'CWE.88.VPPD' for original rule ID: 'SEC.VPPD' (All CWEs)
                        if (parsedCWENumber == 74
                                || parsedCWENumber == 79
                                || parsedCWENumber == 80
                                || parsedCWENumber == 88
                                || parsedCWENumber == 352) return returnValue;
                        break;
                    case 22: // Path Traversal
                        // category 'CWE.434.TDFNAMES' for original rule ID: 'BD.SECURITY.TDFNAMES'
                        // dotTEST: 'CWE.20.TDFNAMES' for original rule ID: 'BD.SECURITY.TDFNAMES'
                        // dotTEST: 'CWE.74.TDFNAMES' for original rule ID: 'BD.SECURITY.TDFNAMES'
                        // dotTEST: 'CWE.99.TDFNAMES' for original rule ID: 'BD.SECURITY.TDFNAMES'
                        // (All CWEs)
                        // dotTEST: 'CWE.668.SCS0018' for original rule ID: 'ROSLYN.SCS.INJ.SCS0018'
                        // cppTEST: BD-SECURITY-TDFNAMES where original 'cat' is: 'CWE-20-i'
                        if (parsedCWENumber == 20
                                || parsedCWENumber == 74
                                || parsedCWENumber == 99
                                || parsedCWENumber == 434
                                || parsedCWENumber == 668) return returnValue;
                        break;
                    case 77: // Command Injection
                        // SECURITY.WSC.APIBS where original 'cat' is: 'CWE.20.APIBS'
                        // dotTEST: 'CWE.74.TDCMD' for original rule ID: 'BD.SECURITY.TDCMD'
                        // dotTEST: 'CWE.78.TDCMD' for original rule ID: 'BD.SECURITY.TDCMD'
                        // cppTEST: BD-SECURITY-TDCMD where original 'cat' is: 'CWE-20-d'
                        // cppTEST: BD-SECURITY-TDCMD where original 'cat' is: 'CWE-78-a'
                        if (parsedCWENumber == 20 || parsedCWENumber == 74 || parsedCWENumber == 78)
                            return returnValue;
                        break;
                    case 79: // XSS
                        // 'CWE.352.TDXSS' for original rule ID: 'BD.SECURITY.TDXSS'
                        // dotTEST: 'CWE.20.TDXSS' for original rule ID: 'BD.SECURITY.TDXSS'
                        // dotTEST: 'CWE.74.TDXSS' for original rule ID: 'BD.SECURITY.TDXSS'
                        // The above is simply the WRONG mapping
                        if (parsedCWENumber == 20
                                || parsedCWENumber == 74
                                || parsedCWENumber == 352) return returnValue;
                        break;
                    case 89: // SQLi Injection
                        // dotTEST: BD.SECURITY.TDSQLC where original 'cat' is: 'CWE.20.TDSQLC'
                        // dotTEST: 'CWE.74.TDSQLC' for original rule ID: 'BD.SECURITY.TDSQLC'
                        // The above is simply the WRONG mapping
                        if (parsedCWENumber == 20 || parsedCWENumber == 74) return returnValue;
                        break;
                    case 90: // LDAP Injection
                        // dotTEST: 'CWE.74.TDLDAP' for original rule ID: 'BD.SECURITY.TDLDAP'
                        // dotTEST: ROSLYN.SCS.INJ.SCS0031 where original 'cat' is: 'CWE.74.SCS0031'
                        // The above is too generic (i.e., just injection)
                        if (parsedCWENumber == 74) return returnValue;
                    case 94: // Code Injection
                        // dotTEST: 'CWE.74.TDCODE' for original rule ID: 'BD.SECURITY.TDCODE'
                        // The above is too generic (i.e., just injection)
                        if (parsedCWENumber == 74) return returnValue;
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
                    case 113: // HTTP Request/Response Splitting
                        // 'CWE.20.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                        // 'CWE.79.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                        // 'CWE.352.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                        // dotTEST: 'CWE.74.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                        // dotTESTL 'CWE.80.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                        // dotTEST: 'CWE.601.TDRESP' for original rule ID: 'BD.SECURITY.TDRESP'
                        if (parsedCWENumber == 20
                                || parsedCWENumber == 74
                                || parsedCWENumber == 79
                                || parsedCWENumber == 80
                                || parsedCWENumber == 352
                                || parsedCWENumber == 601) return returnValue;
                        break;
                    case 119: //
                        // cppTest: BD-PB-ARRAY where original 'cat' is: 'CWE-125-a'
                        // cppTest: BD-PB-ARRAY where original 'cat' is: 'CWE-787-a'
                        // cppTest: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-20-a'
                        // cppTest: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-125-e'
                        // cppTest: BD-SECURITY-ARRAY where original 'cat' is: 'CWE-787-h'
                        if (parsedCWENumber == 20
                                || parsedCWENumber == 125
                                || parsedCWENumber == 787) return returnValue;
                    case 125: // Out-of-bounds Read
                        // cppTEST: BD-SECURITY-OVERFRD where original 'cat' is: 'CWE-119-h'
                        // cppTest: BD-PB-OVERFRD where original 'cat' is: 'CWE-119-d'
                        if (parsedCWENumber == 119) return returnValue;
                    case 129: // Improper Validation of Array Index
                        // PB.RE.CAI where original 'cat' is: 'CWE.20.CAI'
                        // Seems like above is in the wrong CWE
                        // category 'CWE.20.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                        // category 'CWE.119.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                        // category 'CWE.125.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                        // category 'CWE.787.ARRAY' for original rule ID: 'BD.PB.ARRAY'
                        if (parsedCWENumber == 20
                                || parsedCWENumber == 119
                                || parsedCWENumber == 125
                                || parsedCWENumber == 787) return returnValue;
                    case 134: // Use of Externally-Controlled Format String
                        // BD.SECURITY.TDINPUT where original 'cat' is: 'CWE.20.TDINPUT'
                        // cppTEST: BD-SECURITY-TDINPUT where original 'cat' is: 'CWE-20-g'
                        // dotTEST: 'CWE.668.TDINPUT' for original rule ID: 'BD.SECURITY.TDINPUT'
                        // The above are simply the WRONG mappings
                        if (parsedCWENumber == 20 || parsedCWENumber == 668) return returnValue;
                        break;
                    case 190: // Integer Overflow or Wraparound
                        // BD.PB.INTWRAP where original 'cat' is: 'CWE.20.INTWRAP'
                        // dotTEST: 'CWE.191.INTWRAP' for original rule ID: 'BD.PB.INTWRAP' (All
                        // CWEs)
                        // cppTEST: BD-SECURITY-TDINTOVERF where original 'cat' is: 'CWE-20-b'
                        if (parsedCWENumber == 20 || parsedCWENumber == 191) return returnValue;
                        break;
                    case 197: // Numeric Truncation Error
                        // gotTEST: BD.PB.INTDL where original cat is'CWE.681.INTDL' (All CWEs)
                        if (parsedCWENumber == 681) return returnValue;
                        break;
                    case 200: // Exposure of Sensitive Info to Unauthorized Actor
                        // 'CWE.502.SSSD' for original rule ID: 'BD.SECURITY.SSSD'
                        // dotTEST: 'CWE.209.SENS' for original rule ID: 'BD.SECURITY.SENS' (All
                        // CWEs)
                        // dotTEST: 'CWE.668.SENS' for original rule ID: 'BD.SECURITY.SENS'
                        // cppTEST: BD-SECURITY-TDCONSOLE where original 'cat' is: 'CWE-20-e'
                        // The above seems like the WRONG mappings
                        if (parsedCWENumber == 20
                                || parsedCWENumber == 209
                                || parsedCWENumber == 502
                                || parsedCWENumber == 668) return returnValue;
                        break;
                    case 256: // Plaintext Storage of a Password
                        // BD.SECURITY.TDPASSWD where original 'cat' is: 'CWE.287.TDPASSWD'
                        // The above seems like the WRONG mapping
                        // dotTEST: 'CWE.522.TDPASSWD' for original rule ID: 'BD.SECURITY.TDPASSWD'
                        // dotTEST: 'CWE.668.TDPASSWD' for original rule ID: 'BD.SECURITY.TDPASSWD'
                        if (parsedCWENumber == 287
                                || parsedCWENumber == 522
                                || parsedCWENumber == 668) return returnValue;
                        break;
                    case 259: // Use of Hard-Coded Password
                        // SECURITY.WSC.HCCS where original 'cat' is: 'CWE.287.HCCS'
                        // SECURITY.WSC.HCCS where original 'cat' is: 'CWE.798.HCCS'
                        // Above seem like the wrong mapping. Should be more specific like this.
                        // dotTEST: ROSLYN.SCS.PWM.SCS0015 original 'cat' is: 'CWE.798.SCS0015'
                        if (parsedCWENumber == 287 || parsedCWENumber == 798) return returnValue;
                        break;
                    case 306: // Missing Authentication for Critical Function
                        // SECURITY.WSC.SSM where original 'cat' is: 'CWE.287.SSM'
                        if (parsedCWENumber == 287) return returnValue;
                        break;
                    case 350: // Reliance on Reverse DNS Resolution for Security-Critical Action
                        // SECURITY.WSC.DNSL where original 'cat' is: 'CWE.287.DNSL'
                        // dotTEST: SEC.WEB.IIPHEU where original 'cat' is: 'CWE.287.IIPHEU'
                        // The above is simply the WRONG mapping
                        if (parsedCWENumber == 287) return returnValue;
                        break;
                    case 311: // Missing Encryption of Sensitive Data
                        // SECURITY.WSC.USC where original 'cat' is: 'CWE.287.USC'
                        if (parsedCWENumber == 287) return returnValue;
                        break;
                    case 321: // Use of Hard-Coded Cryptographic Key
                        // SECURITY.WSC.HCCK where original 'cat' is: 'CWE.287.HCCK'
                        // SECURITY.WSC.HCCK where original 'cat' is: 'CWE.798.HCCK'
                        // dotTEST: ROSLYN.MSNA.SECURITY.CA5390 original 'cat' is: 'CWE.287.CA5390'
                        // Above seem like the wrong mapping. Should be more specific like this.
                        if (parsedCWENumber == 287 || parsedCWENumber == 798) return returnValue;
                        break;
                    case 362: // Race Condition
                        // dotTEST: 'CWE.662.DIFCS' for original rule ID: 'BD.TRS.DIFCS' (All CWEs)
                        if (parsedCWENumber == 662) return returnValue;
                        break;
                    case 383: // J2EE Bad Practice: Direct Use of Threads
                        // TRS.ISTART where original 'cat' is: 'CWE.400.ISTART'
                        // The above is simply the WRONG mapping
                        if (parsedCWENumber == 400) return returnValue;
                        break;
                    case 395: // Use of NPE Catch to Detect Null Pointer Dereference
                        // 'CWE.476.NP' for original rule ID: 'BD.EXCEPT.NP'
                        // 476 is Null Pointer Dereference
                        if (parsedCWENumber == 476) return returnValue;
                        break;
                    case 400: // Uncontrolled Resource Consumption
                        // dotTEST: 'CWE.771.LEAKS' for original rule ID: 'BD.RES.LEAKS' (All CWEs)
                        // dotTEST: 'CWE.772.LEAKS' for original rule ID: 'BD.RES.LEAKS' (All CWEs)
                        if (parsedCWENumber == 771 || parsedCWENumber == 772) return returnValue;
                        break;
                    case 426: // Untrusted Search Path
                        // dotTEST: SEC.PBRTE where original 'cat' is: 'CWE.668.PBRTE'
                        // The above is too generic a mapping. Should be 426
                        if (parsedCWENumber == 668) return returnValue;
                        break;
                    case 470: // Unsafe Reflection
                        // BD.SECURITY.TDRFL where original 'cat' is: 'CWE.20.TDRFL'
                        // The above is simply the WRONG mapping
                        if (parsedCWENumber == 20) return returnValue;
                        break;
                    case 501: // Trust Boundary Violation
                        // cppTEST: BD-SECURITY-TDENV where original 'cat' is: 'CWE-20-f'
                        // The above is simply the WRONG mapping
                        if (parsedCWENumber == 20) return returnValue;
                    case 532: // Insertion of Sensitive Info into Log File
                        // BD.SECURITY.TDLOG where original 'cat' is: 'CWE.20.TDLOG'
                        // SECURITY.ESD.CONSEN where original 'cat' is: 'CWE.200.CONSEN'
                        // The above are simply the WRONG mapping
                        if (parsedCWENumber == 20 || parsedCWENumber == 200) return returnValue;
                        break;
                    case 561: // Dead Code
                        // dotTEST: 'CWE.705.ANIL' for original rule ID: 'CS.PB.ANIL' (All CWEs)
                        // dotTEST: 'CWE.1069.EEB' for original rule ID: 'CS.PB.EEB' (All CWEs)
                        if (parsedCWENumber == 705 || parsedCWENumber == 1069) return returnValue;
                        break;
                    case 569: // Expression Issues (usually always false (570) or always true (571)
                        // dotTEST: 'CWE.570.CC' for original rule ID: 'BD.PB.CC' (All CWEs)
                        // dotTEST: 'CWE.571.CC' for original rule ID: 'BD.PB.CC' (All CWEs)
                        if (parsedCWENumber == 570 || parsedCWENumber == 571) return returnValue;
                        break;
                    case 606: // Unchecked Input for Loop Condition
                        // cppTEST: BD-SECURITY-TDLOOP where original 'cat' is: 'CWE-400-b'
                        // cppTEST: 'CWE-20-j' for original rule ID: 'SECURITY-38'
                        // The above are simply the WRONG mapping
                        if (parsedCWENumber == 20 || parsedCWENumber == 400) return returnValue;
                    case 643: // XPath Injection
                        // dotTEST: ROSLYN.SCS.INJ.SCS0003 where original 'cat' is: 'CWE.74.SCS0003'
                        // The above is too generic a mapping. Should be 643
                        if (parsedCWENumber == 74) return returnValue;
                        break;
                    case 675: // Multiple Operations on Resource in Single-Operational Context
                        // dotTEST: 'CWE.416.DISP' for original rule ID: 'BD.PB.DISP'
                        if (parsedCWENumber == 416) return returnValue;
                        break;
                    case 703: // Improper Check or Handling of Exceptional Conditions
                        // dotTEST: 'CWE.391.LGE' for original rule ID: 'SEC.LGE' (All CWEs)
                        if (parsedCWENumber == 391) return returnValue;
                        break;
                    case 787: // Out-of-bounds Write
                        // cppTest: BD-PB-OVERFWR where original 'cat' is: 'CWE-119-e'
                        // cppTEST: BD-PB-PATHBUF where original 'cat' is: 'CWE-119-k'
                        // cppTEST: BD-SECURITY-OVERFWR where original 'cat' is: 'CWE-119-i'
                        if (parsedCWENumber == 119) return returnValue;
                        break;
                    case 1004: // Missing HttpOnly on Sensitive Cookies
                        // dotTEST: ROSLYN.MSNA.SECURITY.CA5396 where original 'cat' is:
                        // 'CWE.668.CA5396'
                        // dotTEST: ROSLYN.MSNA.SECURITY.CA5396 where original 'cat' is:
                        // 'CWE.732.CA5396' and rule origId (which might be null) is:
                        // 'ROSLYN.MSNA.SECURITY.CA5396'
                        // The above are simply the WRONG mappings
                        if (parsedCWENumber == 668 || parsedCWENumber == 732) return returnValue;
                        break;
                }
                System.err.println(
                        "WARNING: computed cweVal of: "
                                + returnValue
                                + " does not match CWE # from CWE category: '"
                                + originalCategory
                                + "' for original rule ID: '"
                                + origId
                                + "'");
            }
        }
    }
}
