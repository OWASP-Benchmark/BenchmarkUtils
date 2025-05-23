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
 * @author Nacho Guisado Obregón, Dave Wichers
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SemgrepReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.json().has("results")
                && resultFile.json().has("errors");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Semgrep", false, TestSuiteResults.ToolType.SAST);

        // get engine version
        try {
            String version = resultFile.json().getString("version");
            tr.setToolVersion(version);
        } catch (JSONException e) {
            // If there is no version value, ignore it.
        }

        JSONArray results = resultFile.json().getJSONArray("results");

        // duration time

        // results
        for (int i = 0; i < results.length(); i++) {
            TestCaseResult tcr = parseSemgrepFindings(results.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    public static int translate(int cwe) {

        switch (cwe) {
            case 11: // ASP.NET Misconfiguration: Creating Debug Binary
            case 14: // Compiler Removal of Code to Clear Buffers
            case 16: // CWE vuln mapping PROHIBITED: Configuration
            case 20: // CWE vuln mapping DISCOURAGED: Improper Input Validation
            case 73: // External Control of File Name or Path
            case 74: // CWE vuln mapping DISCOURAGED: Improper Neutralization of Special Elements in
                // Output Used by a Downstream Component ('Injection')
            case 75: // CWE vuln mapping DISCOURAGED: Failure to Sanitize Special Elements into a
                // Different Plane (Special Element Injection)
            case 77: // Improper Neutralization of Special Elements used in a Command ('Command
                // Injection') - TODO: Map to Command Injection?
            case 91: // XML Injection (aka Blind XPath Injection)
            case 93: // Improper Neutralization of CRLF Sequences ('CRLF Injection')
            case 94: // Improper Control of Generation of Code ('Code Injection') - Reported when it
                // sees JS eval() being used.
            case 95: // Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval
                // Injection')
            case 96: // Improper Neutralization of Directives in Statically Saved Code ('Static Code
                // Injection')
            case 113: // Header injection
            case 114: // Process Control
            case 115: // Misinterpretation of Input
            case 116: // Improper Encoding or Escaping of Output
            case 117: // Improper Output Neutralization for Logs
            case 119: // CWE vuln mapping DISCOURAGED: Improper Restriction of Operations within the
                // Bounds of a Memory Buffer
            case 120: // Classic Buffer Overflow
            case 125: // Out of bounds Read
            case 131: // Incorrect Calculation of Buffer Size
            case 134: // Use of Externally-Controlled Format String
            case 150: // Improper Neutralization of Escape, Meta, or Control Sequences
            case 155: // Improper Neutralization of Wildcards or Matching Symbols
            case 183: // Permissive List of Allowed Inputs
            case 190: // Integer Overflow or Wraparound
            case 200: // Information Leak / Disclosure
            case 209: // Generation of Error Message Containing Sensitive Information
            case 242: // Use of Inherently Dangerous Function
            case 250: // Execution with Unnecessary Privileges
            case 252: // Unchecked Return Value
            case 259: // Use of Hard-coded Password
            case 262: // Not Using Password Aging
            case 264: // CWE vuln mapping PROHIBITED: Permissions, Privileges, and Access Controls
            case 269: // CWE vuln mapping DISCOURAGED: Improper Privilege Management
            case 272: // Least Privilege Violation
            case 276: // Incorrect Default Permissions
            case 284: // CWE vuln mapping DISCOURAGED: Improper Access Control
            case 287: // CWE vuln mapping DISCOURAGED: Improper Authentication
            case 295: // Improper Certificate Validation
            case 296: // Improper Following of Certificate's Chain of Trust
            case 297: // Improper Validation of Certificate with Host Mismatch
            case 300: // CWE vuln mapping DISCOURAGED: Channel Accessible by Non-Endpoint
            case 305: // Authentication Bypass by Primary Weakness
            case 306: // Missing Authentication for Critical Function
            case 310: // CWE vuln mapping PROHIBITED: Cryptographic Issues
            case 311: // CWE vuln mapping DISCOURAGED: Missing Encryption of Sensitive Data
            case 319: // Cleartext Transmission of Sensitive Into (e.g., not using HTTPS)
            case 320: // CWE vuln mapping PROHIBITED: Key Management Errors
            case 321: // Hard-coded Crypto Key
            case 322: // Key Exchange without Entity Authentication
            case 323: // Reusing a Nonce, Key Pair in Encryption
            case 337: // Predictable Seed in Pseudo-Random Number Generator (PRNG)
            case 341: // Predictable from Observable State
            case 345: // CWE vuln mapping DISCOURAGED: Insufficient Verification of Data
                // Authenticity
            case 346: // Origin Validation Error
            case 353: // Missing Support for Integrity Check
            case 352: // CSRF
            case 362: // Race Condition
            case 367: // Time-of-check Time-of-use (TOCTOU) Race Condition
            case 369: // Divide By Zero
            case 377: // Insecure Temporary File
            case 384: // Session Fixation
            case 400: // CWE vuln mapping DISCOURAGED: Uncontrolled Resource Consumption
            case 406: // Insufficient Control of Network Message Volume (Network Amplification)
            case 415: // Double Free
            case 416: // Use After Free
            case 441: // Unintended Proxy or Intermediary ('Confused Deputy')
            case 444: // HTTP Request/Response Smuggling
            case 451: // User Interface (UI) Misrepresentation of Critical Information
            case 454: // External Initialization of Trusted Variables or Data Stores
            case 467: // Use of sizeof() on a Pointer Type
            case 470: // Unsafe Reflection
            case 476: // NULL Pointer Dereference
            case 477: // Use of Obsolete Function
            case 489: // Active Debug Code
            case 502: // Deserialization of Untrusted Data
            case 521: // Weak Password Requirements
            case 522: // Insufficiently Protected Credentials
            case 523: // Unprotected Transport of Credentials
            case 532: // Insertion of Sensitive Information into Log File
            case 538: // Insertion of Sensitive Information into Externally-Accessible File or
                // Directory
            case 548: // Exposure of Information Through Directory Listing
            case 553: // Command Shell in Externally Accessible Directory
            case 601: // URL Redirection to Untrusted Site ('Open Redirect')
            case 613: // Insufficient Session Expiration
            case 639: // Authorization Bypass Through User-Controlled Key
            case 644: // Improper Neutralization of HTTP Headers for Scripting Syntax
            case 665: // CWE vuln mapping DISCOURAGED: Improper Initialization
            case 667: // Improper Locking
            case 668: // CWE vuln mapping DISCOURAGED: Exposure of Resource to Wrong Sphere
            case 676: // Use of Potentially Dangerous Function
            case 681: // Incorrect Conversion between Numeric Types
            case 682: // CWE vuln mapping DISCOURAGED: Incorrect Calculation
            case 688: // Function Call With Incorrect Variable or Reference as Argument
            case 693: // CWE vuln mapping DISCOURAGED: Protection Mechanism Failure
            case 697: // CWE vuln mapping DISCOURAGED: Incorrect Comparison
            case 704: // Incorrect Type Conversion or Cast
            case 706: // Use of Incorrectly-Resolved Name or Reference
            case 732: // Incorrect Permission Assignment for Critical Resource
            case 749: // Exposed Dangerous Method or Function
            case 757: // Selection of Less-Secure Algorithm During Negotiation ('Algorithm
                // Downgrade')
            case 774: // Allocation of File Descriptors or Handles Without Limits or Throttling
            case 776: // XEE: Improper Restriction of Recursive Entity References in DTDs ('XML
                // Entity Expansion')
            case 778: // Insufficient Logging
            case 780: // Use of RSA Algorithm without OAEP
                // TODO: Map to Weak Crypto?
            case 787: // Out of bounds Write
            case 798: // Use of Hard-coded Credentials
            case 837: // Improper Enforcement of a Single, Unique Action
            case 841: // Improper Enforcement of Behavioral Workflow
            case 913: // Improper Control of Dynamically-Managed Code Resources
            case 915: // Improperly Controlled Modification of Dynamically-Determined Object
                // Attributes
            case 916: // Use of Password Hash With Insufficient Computational Effort
            case 918: // SSRF
            case 922: // Insecure Storage of Sensitive Information
            case 926: // Improper Export of Android Application Components
            case 939: // Improper Authorization in Handler for Custom URL Scheme
            case 942: // Permissive Cross-domain Policy with Untrusted Domains
            case 943: // Improper Neutralization of Special Elements in Data Query Logic
                // TODO: Map this as parent of for various Injection flaw CWEs in Benchmark
            case 1021: // TapJacking: Improper Restriction of Rendered UI Layers or Frames
            case 1104: // Use of Unmaintained Third Party Components
            case 1204: // Generation of Weak Initialization Vector (IV)
            case 1275: // Sensitive Cookie with Improper SameSite Attribute
            case 1323: // Improper Management of Sensitive Trace Data
            case 1333: // Inefficient Regular Expression Complexity (e.g., RegexDOS)
            case 1336: // Improper Neutralization of Special Elements Used in a Template Engine
                // TODO: Map to some type of injection?
            case 1390: // Weak Authentication
                break; // Don't care - So return CWE 'as is'

            case 22: // Improper Limitation of a Pathname to a Restricted Directory ('Path
                // Traversal')
            case 23: // Relative Path Traversal
            case 35: // Path Traversal: '.../...//'
                return CweNumber.PATH_TRAVERSAL;
            case 78:
                return CweNumber.COMMAND_INJECTION;
            case 79:
            case 80: // Basic XSS
                return CweNumber.XSS;
            case 89:
                return CweNumber.SQL_INJECTION;
            case 90:
                return CweNumber.LDAP_INJECTION;
            case 326:
            case 327:
            case 329: // Generation of Predictable IV with CBC Mode - Has no affect on Benchmark -
                // but leaving mapping in anyway
            case 696: // Incorrect Behavior Order
                return CweNumber.WEAK_CRYPTO_ALGO; // weak encryption
            case 328:
                return CweNumber.WEAK_HASH_ALGO;
            case 330: // Use of Insufficiently Random Values - Vuln mapping discouraged
            case 338: // Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)
                return CweNumber.WEAK_RANDOM;
            case 501:
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case 611: // Improper Restriction of XML External Entity Reference (XXE)
                return CweNumber.XXE;
            case 614:
                return CweNumber.INSECURE_COOKIE;
            case 643:
                return CweNumber.XPATH_INJECTION;
            case 1004:
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;
            default:
                System.out.println(
                        "INFO: Found following CWE in SemGrep results which we haven't seen before: "
                                + cwe);
        }
        return cwe;
    }

    private TestCaseResult parseSemgrepFindings(JSONObject result) {
        /*
        {
            "check_id": "java.lang.security.audit.formatted-sql-string.formatted-sql-string",
            "path": "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02738.java",
            "start": {
                "line": 48,
                "col": 3
            },
            "end": {
                "line": 62,
                "col": 4
            },
            "extra": {
                "message": "Detected a formatted string in a SQL statement. This could lead to SQL\ninjection if variables in the SQL statement are not properly sanitized.\nUse a prepared statements (java.sql.PreparedStatement) instead. You\ncan obtain a PreparedStatement using 'connection.prepareStatement'.\n",
                "metavars": {
                    "$W": {
                        "start": {
                            "line": 52,
                            "col": 4,
                            "offset": 2060
                        },
                        "end": {
                            "line": 52,
                            "col": 13,
                            "offset": 2069
                        },
                        "abstract_content": "statement",
                        "unique_id": {
                            "type": "id",
                            "value": "statement",
                            "kind": "Local",
                            "sid": 16
                        }
                    },
                    "$Y": {
                        "start": {
                            "line": 48,
                            "col": 80,
                            "offset": 1938
                        },
                        "end": {
                            "line": 48,
                            "col": 83,
                            "offset": 1941
                        },
                        "abstract_content": "\"'\"",
                        "unique_id": {
                            "type": "AST",
                            "md5sum": "a49ef1cc4c90797113e4bfc4fea284c2"
                        }
                    },
                    "$X": {
                        "start": {
                            "line": 48,
                            "col": 16,
                            "offset": 1874
                        },
                        "end": {
                            "line": 48,
                            "col": 78,
                            "offset": 1936
                        },
                        "abstract_content": "\"SELECT * from USERS where USERNAME='foo' and PASSWORD='\"+bar",
                        "unique_id": {
                            "type": "AST",
                            "md5sum": "c06a8ea6cc3be92766bd8a358308b20a"
                        }
                    },
                    "$SQL": {
                        "start": {
                            "line": 48,
                            "col": 10,
                            "offset": 1868
                        },
                        "end": {
                            "line": 48,
                            "col": 13,
                            "offset": 1871
                        },
                        "abstract_content": "sql",
                        "unique_id": {
                            "type": "id",
                            "value": "sql",
                            "kind": "Local",
                            "sid": 15
                        }
                    }
                },
                "metadata": {
                    "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
                    "owasp": "A1: Injection",
                    "source-rule-url": "https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION",
                    "references": [
                        "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                        "https://docs.oracle.com/javase/tutorial/jdbc/basics/prepared.html#create_ps",
                        "https://software-security.sans.org/developer-how-to/fix-sql-injection-in-java-using-prepared-callable-statement"
                    ]
                },
                "severity": "WARNING",
                "lines": "\t\tString sql = \"SELECT * from USERS where USERNAME='foo' and PASSWORD='\"+ bar +\"'\";\n\t\t\t\t\n\t\ttry {\n\t\t\tjava.sql.Statement statement =  org.owasp.benchmark.helpers.DatabaseHelper.getSqlStatement();\n\t\t\tstatement.execute( sql );\n            org.owasp.benchmark.helpers.DatabaseHelper.printResults(statement, sql, response);\n\t\t} catch (java.sql.SQLException e) {\n\t\t\tif (org.owasp.benchmark.helpers.DatabaseHelper.hideSQLErrors) {\n        \t\tresponse.getWriter().println(\n\"Error processing request.\"\n);\n        \t\treturn;\n        \t}\n\t\t\telse throw new ServletException(e);\n\t\t}"
            }
        }
         */
        try {
            String className = result.getString("path");
            className = (className.substring(className.lastIndexOf('/') + 1)).split("\\.")[0];
            if (className.startsWith(BenchmarkScore.TESTCASENAME)) {

                TestCaseResult tcr = new TestCaseResult();

                JSONObject extra = result.getJSONObject("extra");
                JSONObject metadata = extra.getJSONObject("metadata");

                // CWE
                String cweString = getStringOrFirstArrayIndex(metadata, "cwe");
                int cwe = Integer.parseInt(cweString.split(":")[0].split("-")[1]);

                try {
                    cwe = translate(cwe);
                } catch (NumberFormatException ex) {
                    System.out.println("CWE # not parseable from: " + metadata.getString("cwe"));
                }

                // category
                String category = getStringOrFirstArrayIndex(metadata, "owasp");

                // evidence
                String evidence = result.getString("check_id");

                tcr.setCWE(cwe);
                tcr.setCategory(category);
                tcr.setEvidence(evidence);
                tcr.setConfidence(0);
                tcr.setNumber(testNumber(className));

                return tcr;
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    private static String getStringOrFirstArrayIndex(JSONObject metadata, String key) {
        if (metadata.get(key) instanceof JSONArray) {
            return metadata.getJSONArray(key).getString(0);
        } else {
            return metadata.getString(key);
        }
    }
}
