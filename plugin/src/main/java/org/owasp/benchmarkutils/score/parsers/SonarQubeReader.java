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
        // not just one, we have to wrap the contents in a <sonar> element so the XML can be
        // parsed properly by the DocumentBuilder. Without this, you get an error like:
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
        tcr.setCWE(cweLookup(rule.substring("java:".length())));

        String cat = getNamedChild("message", flaw).getTextContent();
        tcr.setEvidence(cat);

        String testfile = getNamedChild("component", flaw).getTextContent().trim();
        testfile = testfile.substring(testfile.lastIndexOf('/') + 1);
        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(testfile));
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
            tcr.setNumber(testNumber(testfile));
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

    public static int cweLookup(String squidNumber) {
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
            case "S864":
                return CweNumber
                        .OPERATOR_PRECEDENCE_LOGIC; // Limited dependence should be placed on
                // operator precedence rules in expressions
            case "S888":
                return CweNumber
                        .LOOP_WITH_UNREACHABLE_EXIT; // Relational operators should be used in "for"
                // loop termination conditions
            case "S899":
                return CweNumber
                        .IMPROPER_CHECK_FOR_CONDITIONS; // Return values should not be ignored when
                // they contain the operation status code
            case "S1066":
                return CweNumber.DONTCARE; // Collapsible "if" statements should be merged
            case "S1075":
                return CweNumber.DONTCARE; // URIs should not be hard coded
            case "S1104": // Class variable fields should not have public accessibility
                return CweNumber.PUBLIC_VAR_WITHOUT_FINAL;
            case "S1116":
                return CweNumber.DONTCARE; // Empty statements should be removed
            case "S1117":
                return CweNumber.DONTCARE; // Local variables should not shadow class fields
            case "S1118":
                return CweNumber.DONTCARE; // Utility classes should not have public constructors
            case "S1128":
                return CweNumber.DONTCARE; // Unnecessary imports should be removed
            case "S1130":
                return CweNumber.DONTCARE; // "throws" declarations should not be superfluous
            case "S1132":
                return CweNumber
                        .DONTCARE; // Strings literals should be placed on the left side when
                // checking for equality
            case "S1134":
                return CweNumber.DONTCARE; // Track uses of "FIXME" tags
            case "S1135":
                return CweNumber.DONTCARE; // Track uses of "TODO" tags
            case "S1141":
                return CweNumber.DONTCARE; // Try-catch blocks should not be nested
            case "S1143":
                return CweNumber.RETURN_INSIDE_FINALLY; // "return " statements should not occur in
                // "finally" blocks
            case "S1144":
                return CweNumber.DONTCARE; // Unused "private" methods should be removed
            case "S1145":
                return CweNumber
                        .DONTCARE; // "if" statement conditions should not unconditionally evaluate
                // to"true" or to"false"
            case "S1147":
                return CweNumber.SYSTEM_EXIT; // Exit methods should not be called
            case "S1149":
                return CweNumber
                        .DONTCARE; // Synchronized classes Vector, Hashtable, Stack and StringBuffer
                // should not be used
            case "S1155":
                return CweNumber
                        .DONTCARE; // Collection.isEmpty() should be used to test for emptiness
            case "S1161":
                return CweNumber
                        .DONTCARE; // "@Override" should be used on overriding and implementing
                // methods
            case "S1163":
                return CweNumber.DONTCARE; // Exceptions should not be thrown in finally blocks
            case "S1168":
                return CweNumber
                        .DONTCARE; // Empty arrays and collections should be returned instead of
                // null
            case "S1171":
                return CweNumber.DONTCARE; // Only static class initializers should be used
            case "S1172":
                return CweNumber.DONTCARE; // Unused method parameters should be removed
            case "S1174":
                return CweNumber
                        .FINALIZE_DECLARED_PUBLIC; // "Object.finalize()" should remain protected
                // (versus public) when overriding
            case "S1181":
                return CweNumber
                        .CATCH_GENERIC_EXCEPTION; // Throwable and Error should not be caught
            case "S1182":
                return CweNumber
                        .CLONE_WITHOUT_SUPER_CLONE; // Classes that override "clone" should be
                // "Cloneable" and call "super.clone()"
            case "S1186":
                return CweNumber.DONTCARE; // Methods should not be empty
            case "S1192":
                return CweNumber.DONTCARE; // String literals should not be duplicated
            case "S1197":
                return CweNumber
                        .DONTCARE; // Array designators "[]" should be on the type, not the variable
            case "S1199":
                return CweNumber.DONTCARE; // Nested code blocks should not be used
            case "S1206":
                return CweNumber
                        .OBJECT_MODEL_VIOLATION; // "equals(Object obj)" and"hashCode()" should be
                // overridden in pairs
            case "S1210":
                return CweNumber
                        .DONTCARE; // "equals(Object obj)" should be overridden along with the
                // "compareTo(T obj)" method
            case "S1217": // Thread.run() and Runnable.run() should not be called  directly
                return CweNumber.THREAD_WRONG_CALL;
            case "S1301":
                return CweNumber
                        .DONTCARE; // "switch" statements should have at least 3 "case" clauses
            case "S1481":
                return CweNumber.DONTCARE; // Remove this unused "c" local variable.
            case "S1444":
                return CweNumber.PUBLIC_STATIC_NOT_FINAL; // "public static" fields should always be
                // constant
            case "S1479":
                return CweNumber
                        .DONTCARE; // "switch" statements should not have too many "case" clauses
            case "S1488":
                return CweNumber
                        .DONTCARE; // Local variables should not be declared and then immediately
                // returned or thrown
            case "S1643":
                return CweNumber.DONTCARE; // Strings should not be concatenated using '+' in a loop
            case "S1659":
                return CweNumber
                        .DONTCARE; // Multiple variables should not be declared on the same line
            case "S1696": // "NullPointerException" should not be caught
                return CweNumber.CATCHING_NULL_POINTER_EXCEPTION;
            case "S1698":
                return CweNumber
                        .OBJECT_REFERENCE_COMPARISON; // Objects should be compared with"equals()"
            case "S1724":
                return CweNumber.DONTCARE; // Deprecated classes and interfaces should not be
                // extended/implemented
            case "S1850":
                return CweNumber
                        .DONTCARE; // "instanceof" operators that always return "true" or"false"
                // should be removed
            case "S1854":
                return CweNumber.UNUSED_VAR_ASSIGNMENT; // Unused assignments should be removed
            case "S1872":
                return 486; // Classes should not be compared by name
            case "S1873":
                return 582; // "static final" arrays should be"private"
            case "S1874":
                return CweNumber.DONTCARE; // "@Deprecated" code should not be used
            case "S1905":
                return CweNumber.DONTCARE; // Redundant casts should not be used
            case "S1948":
                return 594; // Fields in a"Serializable" class should either be transient or
                // serializable
            case "S1989":
                return 600; // Exceptions should not be thrown from servlet methods
            case "S2068":
                return 259; // Credentials should not be hard-coded
            case "S2070":
                return CweNumber.WEAK_HASH_ALGO; // Benchmark Vuln: SHACweNumber.DONTCARE and
                // Message-Digest hash algorithms should not be used
            case "S2076":
                return CweNumber
                        .COMMAND_INJECTION; // Benchmark Vuln: Values passed to OS commands should
                // be sanitized
            case "S2077":
                return CweNumber
                        .SQL_INJECTION; // Benchmark Vuln: Values passed to SQL commands should be
                // sanitized
            case "S2078":
                return CweNumber
                        .LDAP_INJECTION; // Benchmark Vuln: Values passed to LDAP queries should be
                // sanitized
            case "S2083":
                return CweNumber.PATH_TRAVERSAL; // Benchmark Vuln: I/O function calls should not be
                // vulnerable to path injection attacks
            case "S2089":
                return 293; // HTTP referers should not be relied on
            case "S2091":
                return CweNumber.XPATH_INJECTION; // Benchmark Vuln: XPath expressions should not be
                // vulnerable to injection attacks
            case "S2092":
                return CweNumber.INSECURE_COOKIE; // Benchmark Vuln: Cookies should be "secure"
            case "S2093":
                return CweNumber.DONTCARE; // Try-with-resources should be used
            case "S2095":
                return 459; // Resources should be closed
            case "S2115":
                return 521; // Secure password should be used when connecting to a database
            case "S2130":
                return CweNumber
                        .DONTCARE; // Parsing should be used to convert "Strings" to primitives
            case "S2147":
                return CweNumber.DONTCARE; // Catches should be combined
            case "S2157":
                return CweNumber.DONTCARE; // "Cloneables" should implement "clone"
            case "S2160":
                return CweNumber.DONTCARE; // Subclasses that add fields should override "equals"
            case "S2176":
                return CweNumber
                        .DONTCARE; // Class names should not shadow interfaces or superclasses
            case "S2178":
                return CweNumber.DONTCARE; // Short-circuit logic should be used in boolean contexts
            case "S2184":
                return 190; // Math operands should be cast before assignment
            case "S2222":
                return 459; // Locks should be released
            case "S2225":
                return 476; // "toString()" and"clone()" methods should not return null
            case "S2245":
                return CweNumber
                        .WEAK_RANDOM; // Benchmark Vuln: Pseudorandom number generators (PRNGs)
                // should not be used in secure contexts
            case "S2254":
                return CweNumber
                        .DONTCARE; // "HttpServletRequest.getRequestedSessionId()" should not be
                // used
            case "S2257":
                return CweNumber
                        .WEAK_CRYPTO_ALGO; // Benchmark Vuln: Only standard cryptographic algorithms
                // should be used
            case "S2259":
                return 476; // Null pointers should not be dereferenced
            case "S2275":
                return CweNumber
                        .DONTCARE; // Printf-style format strings should not lead to unexpected
                // behavior at runtime
            case "S2277":
                return 780; // Cryptographic RSA algorithms should always incorporate OAEP (Optimal
                // Asymmetric Encryption Padding)
            case "S2278":
                return CweNumber
                        .WEAK_CRYPTO_ALGO; // Benchmark Vuln: DES (Data Encryption Standard) and
                // DESede (3DES) should not be used
            case "S2293":
                return CweNumber.DONTCARE; // The diamond operator ("<>") should be used
            case "S2384":
                return 374; // Mutable members should not be stored or returned directly
            case "S2386":
                return 607; // Mutable fields should not be "public static"
            case "S2441":
                return 579; // Non-serializable objects should not be stored in"HttpSessions"
            case "S2479":
                return CweNumber
                        .DONTCARE; // Whitespace and control characters in literals should be
                // explicit
            case "S2583":
                return 489; // Conditions should not unconditionally evaluate to"TRUE" or to"FALSE"
            case "S2589":
                return CweNumber
                        .DONTCARE; // Boolean expressions should not be gratuitous - CWEs: 570/571
            case "S2658":
                return 470; // Use of Externally-Controlled Input to Select Classes or Code ('Unsafe
                // Reflection')
            case "S2677":
                return CweNumber.DONTCARE; // "read" and "readLine" return values should be used
            case "S2681":
                return 483; // Multiline blocks should be enclosed in curly braces
            case "S2696":
                return CweNumber.DONTCARE; // Instance methods should not write to "static" fields
            case "S2755":
                return CweNumber.XXE; // XML parsers should not be vulnerable to XXE attacks
            case "S2786":
                return CweNumber.DONTCARE; // Nested "enum"s should not be declared static
            case "S2864":
                return CweNumber
                        .DONTCARE; // "entrySet()" should be iterated when both the key and value
                // are needed
            case "S3008":
                return CweNumber
                        .DONTCARE; // Static non-final field names should comply with a naming
                // convention
            case "S3012":
                return CweNumber.DONTCARE; // Arrays should not be copied using loops
            case "S3400":
                return CweNumber.DONTCARE; // Methods should not return constants
            case "S3518":
                return 369; // Zero should not be a possible denominator
            case "S3599":
                return CweNumber.DONTCARE; // Double Brace Initialization should not be used
            case "S3626":
                return CweNumber.DONTCARE; // Jump statements should not be redundant
            case "S3649":
                return CweNumber
                        .SQL_INJECTION; // Database queries should not be vulnerable to injection
                // attacks
            case "S3740":
                return CweNumber.DONTCARE; // Raw types should not be used
            case "S3776":
                return CweNumber.DONTCARE; // Cognitive Complexity of methods should not be too high
            case "S3824":
                return CweNumber
                        .DONTCARE; // "Map.get" and value test should be replaced with single method
                // call
            case "S3973":
                return CweNumber
                        .DONTCARE; // A conditionally executed single line should be denoted by
                // indentation
            case "S4042":
                return CweNumber.DONTCARE; // "java.nio.Files#delete" should be preferred
            case "S4435":
                return CweNumber.XXE; // XML transformers should be secured
            case "S4488":
                return CweNumber
                        .DONTCARE; // Composed "@RequestMapping" variants should be preferred
            case "S4719":
                return CweNumber.DONTCARE; // "StandardCharsets" constants should be preferred
            case "S4838":
                return CweNumber
                        .DONTCARE; // An iteration on a Collection should be performed on the type
                // handled by the Collection
            case "S5131": // Endpoints should not be vulnerable to reflected cross-site scripting
                // (XSS) attacks
                return CweNumber.XSS;
            case "S5261":
                return CweNumber
                        .DONTCARE; // "else" statements should be clearly matched with an "if"
            case "S5361":
                return CweNumber
                        .DONTCARE; // "String#replace" should be preferred to "String#replaceAll"
            case "S5542":
            case "S5547":
                return CweNumber
                        .WEAK_CRYPTO_ALGO; // Benchmark Vuln: Encryption algorithms should be used
                // with secure mode and padding scheme
            case "S4790":
                // Using weak hashing algorithms is security-sensitive
                return CweNumber.WEAK_HASH_ALGO;
            case "S3330":
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;

            case "S1153":
            case "S2119":
            case "S2129":
            case "S6541":
            case "S6853":
            case "S6851":
            case "CallToDeprecatedMethod":
            case "ClassVariableVisibilityCheck":
            case "DuplicatedBlocks":
            case "SwitchLastCaseIsDefaultCheck":
                return CweNumber.DONTCARE; // Not sure why these are being returned instead of an
                // S#### value
            default:
                System.out.println(
                        "SonarQubeReader: Unknown squid number: "
                                + squidNumber
                                + " has no CWE mapping.");
        }

        return -1;
    }
}
