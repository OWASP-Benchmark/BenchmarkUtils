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

        JSONArray results = resultFile.json().getJSONArray("results");

        // engine version
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

    private int translate(int cwe) {

        switch (cwe) {
            case 113: // Header injection;
            case 200: // Information Leak / Disclosure;
            case 276: // Incorrect Default Permissions;
            case 352: // CSRF;
            case 489: // Active Debug Code;
                break; // Don't care - So return CWE 'as is'

            case 22:
                return CweNumber.PATH_TRAVERSAL;
            case 78:
                return CweNumber.COMMAND_INJECTION;
            case 79:
                return CweNumber.XSS;
            case 89:
                return CweNumber.SQL_INJECTION;
            case 90:
                return CweNumber.LDAP_INJECTION;
            case 326:
            case 327:
            case 696: // Incorrect Behavior Order
                return CweNumber.WEAK_CRYPTO_ALGO; // weak encryption
            case 328:
                return CweNumber.WEAK_HASH_ALGO;
            case 330:
                return CweNumber.WEAK_RANDOM;
            case 501:
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case 614:
            case 1004:
                return CweNumber.INSECURE_COOKIE;
            case 643:
                return CweNumber.XPATH_INJECTION;
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
