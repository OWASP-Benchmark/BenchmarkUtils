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

import java.io.ByteArrayInputStream;
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

public class SonarQubeReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && (resultFile.line(0).startsWith("<total")
                        || resultFile.line(0).startsWith("<p>"));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();

        // Because the Sonar results file is not well formed, i.e., it has multiple root elements,
        // not
        // just one, we have to wrap the contents in a <sonar> element so the XML can be parsed
        // properly
        // by the DocumentBuilder. Without this, you get an error like:
        // org.xml.sax.SAXParseException;
        // lineNumber: X; columnNumber: YY; The markup in the document following the root element
        // must be well-formed.
        String fixed = "<sonar>" + resultFile.content() + "</sonar>";
        InputSource is = new InputSource(new ByteArrayInputStream(fixed.getBytes()));
        Document doc = docBuilder.parse(is);

        // The OLD SonarQube Java Plug XML format simply started with something like:
        //      <total>NUMFINDINGS</total><languages><name>Java</name><key>java</key>
        // while the new (in 2020) XML format from their SaaS portal starts with this:
        //      <p>20</p><total>NUMFINDINGS</total><components><path> ...
        TestSuiteResults tr = null;
        if (fixed.startsWith("<sonar><p>")) {
            // Handle the new XML format
            tr = new TestSuiteResults("SonarQube", false, TestSuiteResults.ToolType.SAST);

            NodeList rootList = doc.getDocumentElement().getChildNodes();

            List<Node> issueList = getNamedNodes("issues", rootList);
            for (Node flaw : issueList) {
                TestCaseResult tcr = parseSonarIssue(flaw);
                if (tcr != null) {
                    tr.put(tcr);
                }
            }

        } else {
            // Handle the legacy XML format
            tr =
                    new TestSuiteResults(
                            "SonarQube Java Plugin", false, TestSuiteResults.ToolType.SAST);

            NodeList rootList = doc.getDocumentElement().getChildNodes();

            List<Node> issueList = getNamedNodes("issues", rootList);

            for (Node flaw : issueList) {
                TestCaseResult tcr = parseSonarPluginIssue(flaw);
                if (tcr != null) {
                    tr.put(tcr);
                }
            }
        }

        // If the filename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml),
        // set the compute time on the score card. TODO: Move this to BenchmarkScore for ALL tools?
        tr.setTime(resultFile.file());

        return tr;
    }

    private TestCaseResult parseSonarIssue(Node flaw) {
        TestCaseResult tcr = new TestCaseResult();
        String rule = getNamedChild("rule", flaw).getTextContent();
        // System.out.println("Rule # is: " + rule);
        tcr.setCWE(cweLookup(rule.substring("java:".length())));

        String cat = getNamedChild("message", flaw).getTextContent();
        tcr.setEvidence(cat);

        String testfile = getNamedChild("component", flaw).getTextContent().trim();
        // System.out.println("Found in component: " + testfile);
        testfile = testfile.substring(testfile.lastIndexOf('/') + 1);
        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            String testno =
                    testfile.substring(
                            BenchmarkScore.TESTCASENAME.length(), testfile.lastIndexOf('.'));
            // System.out.println("Which is determined to be test #: " + testno);
            tcr.setNumber(Integer.parseInt(testno));
            return tcr;
        }
        return null;
    }

    private TestCaseResult parseSonarPluginIssue(Node flaw) {
        TestCaseResult tcr = new TestCaseResult();
        String rule = getNamedChild("rule", flaw).getTextContent();
        tcr.setCWE(cweLookup(rule.substring("squid:".length())));

        String cat = getNamedChild("message", flaw).getTextContent();
        tcr.setCategory(cat);
        tcr.setConfidence(5);
        tcr.setEvidence(cat);

        String testfile = getNamedChild("component", flaw).getTextContent().trim();
        testfile = testfile.substring(testfile.lastIndexOf('/') + 1);
        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            String testno =
                    testfile.substring(
                            BenchmarkScore.TESTCASENAME.length(), testfile.lastIndexOf('.'));
            tcr.setNumber(Integer.parseInt(testno));
            return tcr;
        }
        return null;
    }

    //    //case "Build Misconfiguration" : return 00;
    //    case "Command Injection" : return 78;
    //    case "Cookie Security" : return 614;
    //    case "Cross-Site Scripting" : return 79;
    //    //case "Dead Code" : return 00;
    //    //case "Denial of Service" : return 00;
    //    case "Header Manipulation" : return 113;
    //    case "Insecure Randomness" : return 330;
    //    //case "J2EE Bad Practices" : return 00;
    //    case "LDAP Injection" : return 90;
    //    //case "Missing Check against Null" : return 00;
    //    //case "Null Dereference" : return 00;
    //    case "Password Management" : return 00;
    //    case "Path Manipulation" : return 22;
    //    //case "Poor Error Handling" : return 00;
    //    //case "Poor Logging Practice" : return 00;
    //    //case "Poor Style" : return 00;
    //    //case "Resource Injection" : return 00;
    //    case "SQL Injection" : return 89;
    //    //case "System Information Leak" : return 00;
    //    case "Trust Boundary Violation" : return 501;
    //    //case "Unreleased Resource" : return 00;
    //    //case "Unsafe Reflection" : return 00;
    //    case "Weak Cryptographic Hash" : return 328;
    //    case "Weak Encryption" : return 327;
    //    case "XPath Injection" : return 643;

    public static CweNumber cweLookup(String squidNumber) {
        // To look up these #'s, go here: https://rules.sonarsource.com/java/RSPEC-#### and put just
        // the #'s with no leading zeroes to look up the 'squid' rule.
        switch (squidNumber) {
            case "S100": // Method names should comply with a naming convention
                return CweNumber.DONTCARE;
            case "S105":
            case "S00105": // Replace all tab characters in this file by sequences of white-spaces.
                return CweNumber.DONTCARE;
            case "S106": // Replace this usage of System.out or System.err by a logger.
                return CweNumber.DONTCARE;
            case "S108": // Nested blocks of code should not be left empty
                return CweNumber.DONTCARE;
            case "S112":
            case "S00112": // Generic exceptions should never be thrown
                return CweNumber.THROW_GENERIC_EXCEPTION;
            case "S115": // Constant names should comply with a naming convention
                return CweNumber.DONTCARE;
            case "S116": // Field names should comply with a naming convention
                return CweNumber.DONTCARE;
            case "S117": // Local variable and method parameter names should comply with a naming
                // convention
                return CweNumber.DONTCARE;
            case "S121":
            case "S00121": // Control structures should always use curly braces
                return CweNumber.INCORRECT_BLOCK_DELIMITATION;
            case "S125": // Sections of code should not be commented out
                return CweNumber.DONTCARE;
            case "S128": // Switch cases should end with an unconditional "break" statement
                return CweNumber.OMITTED_BREAK;
            case "S131": // "switch" statements should have "default" clauses
                return CweNumber.MISSING_DEFAULT_CASE;
            case "S135": // Loops should not contain more than a single "break" or "continue"
                // statement
                return CweNumber.DONTCARE;
            case "S864": // Limited dependence should be placed on operator precedence rules in
                // expressions
                return CweNumber.OPERATOR_PRECEDENCE_LOGIC;
            case "S888": // Relational operators should be used in "for" loop termination conditions
                return CweNumber.LOOP_WITH_UNREACHABLE_EXIT;
            case "S899": // Return values should not be ignored when they contain the operation
                // status code
                return CweNumber.IMPROPER_CHECK_FOR_CONDITIONS;
            case "S1066": // Collapsible "if" statements should be merged
                return CweNumber.DONTCARE;
            case "S1075": // URIs should not be hardcoded
                return CweNumber.DONTCARE;
            case "S1104": // Class variable fields should not have public accessibility
                return CweNumber.PUBLIC_VAR_WITHOUT_FINAL;
            case "S1116": // Empty statements should be removed
                return CweNumber.DONTCARE;
            case "S1117": // Local variables should not shadow class fields
                return CweNumber.DONTCARE;
            case "S1118": // Utility classes should not have public constructors
                return CweNumber.DONTCARE;
            case "S1128": // Unnecessary imports should be removed
                return CweNumber.DONTCARE;
            case "S1130": // "throws" declarations should not be superfluous
                return CweNumber.DONTCARE;
            case "S1132": // Strings literals should be placed on the left side when checking for
                // equality
                return CweNumber.DONTCARE;
            case "S1134": // Track uses of "FIXME" tags
                return CweNumber.DONTCARE;
            case "S1135": // Track uses of "TODO" tags
                return CweNumber.DONTCARE;
            case "S1141": // Try-catch blocks should not be nested
                return CweNumber.DONTCARE;
            case "S1143": // "return " statements should not occur in "finally" blocks
                return CweNumber.RETURN_INSIDE_FINALLY;
            case "S1144": // Unused "private" methods should be removed
                return CweNumber.DONTCARE;
            case "S1145": // "if" statement conditions should not unconditionally evaluate to"true"
                // or to"false"
                return CweNumber.DONTCARE;
            case "S1147": // Exit methods should not be called
                return CweNumber.SYSTEM_EXIT;
            case "S1149": // Synchronized classes Vector, Hashtable, Stack and StringBuffer should
                // not be used
                return CweNumber.DONTCARE;
            case "S1155": // Collection.isEmpty() should be used to test for emptiness
                return CweNumber.DONTCARE;
            case "S1161": // "@Override" should be used on overriding and implementing methods
                return CweNumber.DONTCARE;
            case "S1163": // Exceptions should not be thrown in finally blocks
                return CweNumber.DONTCARE;
            case "S1168": // Empty arrays and collections should be returned instead of null
                return CweNumber.DONTCARE;
            case "S1171": // Only static class initializers should be used
                return CweNumber.DONTCARE;
            case "S1172": // Unused method parameters should be removed
                return CweNumber.DONTCARE;
            case "S1174": // "Object.finalize()" should remain protected
                // (versus public) when overriding
                return CweNumber.FINALIZE_DECLARED_PUBLIC;
            case "S1181": // Throwable and Error should not be caught
                return CweNumber.CATCH_GENERIC_EXCEPTION;
            case "S1182": // Classes that override "clone" should be "Cloneable" and call
                // "super.clone()"
                return CweNumber.CLONE_WITHOUT_SUPER_CLONE;
            case "S1186": // Methods should not be empty
                return CweNumber.DONTCARE;
            case "S1192": // String literals should not be duplicated
                return CweNumber.DONTCARE;
            case "S1197": // Array designators "[]" should be on the type, not the variable
                return CweNumber.DONTCARE;
            case "S1199": // Nested code blocks should not be used
                return CweNumber.DONTCARE;
            case "S1206": // "equals(Object obj)" and"hashCode()" should be overridden in pairs
                return CweNumber.OBJECT_MODEL_VIOLATION;
            case "S1210": // "equals(Object obj)" should be overridden along with the "compareTo(T
                // obj)" method
                return CweNumber.DONTCARE;
            case "S1217": // Thread.run() and Runnable.run() should not be called  directly
                return CweNumber.THREAD_WRONG_CALL;
            case "S1301": // "switch" statements should have at least 3 "case" clauses
                return CweNumber.DONTCARE;
            case "S1481": // Remove this unused "c" local variable.
                return CweNumber.DONTCARE;
            case "S1444": // "public static" fields should always be
                return CweNumber.PUBLIC_STATIC_NOT_FINAL;
                // constant
            case "S1479": // "switch" statements should not have too many "case" clauses
                return CweNumber.DONTCARE;
            case "S1488": // Local variables should not be declared and then immediately returned or
                // thrown
                return CweNumber.DONTCARE;
            case "S1643": // Strings should not be concatenated using '+' in a loop
                return CweNumber.DONTCARE;
            case "S1659": // Multiple variables should not be declared on the same line
                return CweNumber.DONTCARE;
            case "S1696": // "NullPointerException" should not be caught
                return CweNumber.CATCHING_NULL_POINTER_EXCEPTION;
            case "S1698": // Objects should be compared with"equals()"
                return CweNumber.OBJECT_REFERENCE_COMPARISON;
            case "S1724": // Deprecated classes and interfaces should not be extended/implemented
                return CweNumber.DONTCARE;
            case "S1850": // "instanceof" operators that always return "true" or"false" should be
                // removed
                return CweNumber.DONTCARE;
            case "S1854": // Unused assignments should be removed
                return CweNumber.UNUSED_VAR_ASSIGNMENT;
            case "S1872": // Classes should not be compared by name
                return CweNumber.COMPARISON_BY_CLASS_NAME;
            case "S1873": // "static final" arrays should be"private"
                return CweNumber.STATIC_FINAL_ARRAY_IS_PUBLIC;
            case "S1874": // "@Deprecated" code should not be used
                return CweNumber.DONTCARE;
            case "S1905": // Redundant casts should not be used
                return CweNumber.DONTCARE;
            case "S1948": // Fields in a"Serializable" class should either be transient or
                // serializable
                return CweNumber.SAVING_UNSERIALIZABLE_OBJECT_TO_DISK;
            case "S1989": // Exceptions should not be thrown from servlet methods
                return CweNumber.UNCAUGHT_EXCEPTION_IN_SERVLET;
            case "S2068": // Credentials should not be hard-coded
                return CweNumber.HARDCODED_PASSWORD;
            case "S2070": // Benchmark Vuln: SHACweNumber.DONTCARE and Message-Digest hash
                // algorithms should not be used
                return CweNumber.WEAK_HASH_ALGO;
            case "S2076": // Benchmark Vuln: Values passed to OS commands should be sanitized
                return CweNumber.OS_COMMAND_INJECTION;
            case "S2077": // Benchmark Vuln: Values passed to SQL commands should be sanitized
                return CweNumber.SQL_INJECTION;
            case "S2078": // Benchmark Vuln: Values passed to LDAP queries should be sanitized
                return CweNumber.LDAP_INJECTION;
            case "S2083": // Benchmark Vuln: I/O function calls should not be vulnerable to path
                // injection attacks
                return CweNumber.PATH_TRAVERSAL;
            case "S2089": // HTTP referers should not be relied on
                return CweNumber.REFERER_FIELD_IN_AUTHENTICATION;
            case "S2091": // Benchmark Vuln: XPath expressions should not be vulnerable to injection
                // attacks
                return CweNumber.XPATH_INJECTION;
            case "S2092": // Benchmark Vuln: Cookies should be "secure"
                return CweNumber.INSECURE_COOKIE;
            case "S2093": // Try-with-resources should be used
                return CweNumber.DONTCARE;
            case "S2095": // Resources should be closed
                return CweNumber.INCOMPLETE_CLEANUP;
            case "S2115": // Secure password should be used when connecting to a database
                return CweNumber.WEAK_PASSWORD_REQUIREMENTS;
            case "S2130": // Parsing should be used to convert "Strings" to primitives
                return CweNumber.DONTCARE;
            case "S2147": // Catches should be combined
                return CweNumber.DONTCARE;
            case "S2157": // "Cloneables" should implement "clone"
                return CweNumber.DONTCARE;
            case "S2160": // Subclasses that add fields should override "equals"
                return CweNumber.DONTCARE;
            case "S2176": // Class names should not shadow interfaces or superclasses
                return CweNumber.DONTCARE;
            case "S2178": // Short-circuit logic should be used in boolean contexts
                return CweNumber.DONTCARE;
            case "S2184": // Math operands should be cast before assignment
                return CweNumber.INTEGER_OVERFLOW_WRAPAROUND;
            case "S2222": // Locks should be released
                return CweNumber.INCOMPLETE_CLEANUP;
            case "S2225": // "toString()" and"clone()" methods should not return null
                return CweNumber.NULL_POINTER_DEREFERENCE;
            case "S2245": // Benchmark Vuln: Pseudorandom number generators (PRNGs) should not be
                // used in secure contexts
                return CweNumber.WEAK_RANDOM;
            case "S2254": // "HttpServletRequest.getRequestedSessionId()" should not be used
                return CweNumber.DONTCARE;
            case "S2257": // Benchmark Vuln: Only standard cryptographic algorithms should be used
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "S2259": // Null pointers should not be dereferenced
                return CweNumber.NULL_POINTER_DEREFERENCE;
            case "S2275": // Printf-style format strings should not lead to unexpected behavior at
                // runtime
                return CweNumber.DONTCARE;
            case "S2277":
                return CweNumber.RSA_MISSING_PADDING; // Cryptographic RSA algorithms should always
                // incorporate OAEP (Optimal Asymmetric Encryption
                // Padding)
            case "S2278": // Benchmark Vuln: DES (Data Encryption Standard) and DESede (3DES) should
                // not be used
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "S2293": // The diamond operator ("<>") should be used
                return CweNumber.DONTCARE;
            case "S2384": // Mutable members should not be stored or returned directly
                return CweNumber.PASS_MUTABLE_OBJECT_TO_UNTRUSTED_MODULE;
            case "S2386": // Mutable fields should not be "public static"
                return CweNumber.PUBLIC_STATIC_FINAL_MUTABLE_OBJECT;
            case "S2441": // Non-serializable objects should not be stored in"HttpSessions"
                return CweNumber.NON_SERIALIZABLE_OBJECT_IN_SESSION;
            case "S2479": // Whitespace and control characters in literals should be explicit
                return CweNumber.DONTCARE;
            case "S2583": // Conditions should not unconditionally evaluate to"TRUE" or to"FALSE"
                return CweNumber.ACTIVE_DEBUG_CODE;
            case "S2589": // Boolean expressions should not be gratuitous - CWEs: 570/571
                return CweNumber.DONTCARE;
            case "S2658": // Use of Externally-Controlled Input to Select Classes or Code ('Unsafe
                // Reflection')
                return CweNumber.UNSAFE_REFLECTION;
            case "S2677": // "read" and "readLine" return values should be used
                return CweNumber.DONTCARE;
            case "S2681": // Multiline blocks should be enclosed in curly braces
                return CweNumber.INCORRECT_BLOCK_DELIMITATION;
            case "S2696":
                return CweNumber.DONTCARE; // Instance methods should not write to "static" fields
            case "S2755":
                return CweNumber.XXE; // XML parsers should not be vulnerable to XXE attacks
            case "S2786":
                return CweNumber.DONTCARE; // Nested "enum"s should not be declared static
            case "S2864": // "entrySet()" should be iterated when both the key and value are needed
                return CweNumber.DONTCARE;
            case "S3008": // Static non-final field names should comply with a naming convention
                return CweNumber.DONTCARE;
            case "S3012": // Arrays should not be copied using loops
                return CweNumber.DONTCARE;
            case "S3400": // Methods should not return constants
                return CweNumber.DONTCARE;
            case "S3518": // Zero should not be a possible denominator
                return CweNumber.DIVISION_BY_ZERO;
            case "S3599": // Double Brace Initialization should not be used
                return CweNumber.DONTCARE;
            case "S3626": // Jump statements should not be redundant
                return CweNumber.DONTCARE;
            case "S3649": // Database queries should not be vulnerable to injection attacks
                return CweNumber.SQL_INJECTION;
            case "S3740": // Raw types should not be used
                return CweNumber.DONTCARE;
            case "S3776": // Cognitive Complexity of methods should not be too high
                return CweNumber.DONTCARE;
            case "S3824": // "Map.get" and value test should be replaced with single method call
                return CweNumber.DONTCARE;
            case "S3973": // A conditionally executed single line should be denoted by indentation
                return CweNumber.DONTCARE;
            case "S4042": // "java.nio.Files#delete" should be preferred
                return CweNumber.DONTCARE;
            case "S4435": // XML transformers should be secured
                return CweNumber.XXE;
            case "S4488": // Composed "@RequestMapping" variants should be preferred
                return CweNumber.DONTCARE;
            case "S4719": // "StandardCharsets" constants should be preferred
                return CweNumber.DONTCARE;
            case "S4838": // An iteration on a Collection should be performed on the type handled by
                // the Collection
                return CweNumber.DONTCARE;
            case "S5131": // Endpoints should not be vulnerable to reflected cross-site scripting
                // (XSS) attacks
                return CweNumber.XSS;
            case "S5261": // "else" statements should be clearly matched with an "if"
                return CweNumber.DONTCARE;
            case "S5361": // "String#replace" should be preferred to "String#replaceAll"
                return CweNumber.DONTCARE;
            case "S5542": // Benchmark Vuln: Encryption algorithms should be used with secure mode
                // and padding scheme
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "S5547": // Benchmark Vuln: Cipher algorithms should be robust
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "CallToDeprecatedMethod":
            case "ClassVariableVisibilityCheck":
            case "DuplicatedBlocks": // Not sure why these are being returned instead of an S####
                // value
            case "SwitchLastCaseIsDefaultCheck":
                return CweNumber.DONTCARE;
            default:
                System.out.println(
                        "SonarQubeReader: Unknown squid number: "
                                + squidNumber
                                + " has no CWE mapping.");
        }

        return CweNumber.DONTCARE;
    }
}
