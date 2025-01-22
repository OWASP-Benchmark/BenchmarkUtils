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
 * @author Dave Wichers
 * @created 2025
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.parsers.FortifyReader;

/**
 * This class scores a SARIF file of Fortify results. Fortify itself can't produce a SARIF file
 * (yet), but an FPR file can be converted to SARIF using the free/open source Microsoft SARIF
 * Multitool.
 *
 * <p>Per: https://github.com/microsoft/sarif-sdk/blob/main/docs/multitool-usage.md:
 *
 * <p>Install the current Sarif.Multitool to the local machine cache (requires Node.js):
 *
 * <p>npm i -g @microsoft/sarif-multitool
 *
 * <p>Run the Sarif.Multitool using the NPM-installed copy: npx @microsoft/sarif-multitool <args>
 *
 * <p>Convert a Fortify file to SARIF:
 *
 * <p>npx @microsoft/sarif-multitool convert Current.fpr --tool FortifyFpr --output Current.sarif
 */
public class FortifySarifReader extends SarifReader {

    public FortifySarifReader() {
        super("MicroFocus Fortify", true, CweSourceType.CUSTOM);
    }

    @Override
    public Map<String, Integer> customRuleCweMappings(JSONObject driver) {
        Map<String, Integer> ruleCweMap = new HashMap<>();

        try {
            JSONArray rules = driver.getJSONObject("driver").getJSONArray("rules");

            for (int i = 0; i < rules.length(); i++) {
                try {
                    JSONObject rule = rules.getJSONObject(i);
                    String ruleId = rule.getString("id");
                    String fullRule = rule.getString("name");
                    String ruleName = fullRule.substring(fullRule.indexOf('/') + 1);

                    // First, try to get mapping from existing FortifyReader
                    switch (ruleName) {
                        case "Build Misconfiguration/External Maven Dependency Repository":
                        case "Cookie Security/Persistent Cookie":
                        case "Password Management/Password in Comment":
                        case "Poor Logging Practice/Use of a System Output Stream":
                            ruleCweMap.put(ruleId, CweNumber.DONTCARE);
                            break;

                        case "Cookie Security/Cookie not Sent Over SSL":
                            ruleCweMap.put(ruleId, CweNumber.INSECURE_COOKIE);
                            break;
                        case "Cookie Security/HTTPOnly not Set":
                            ruleCweMap.put(ruleId, 1004); // CWE-1004 Cookie w/out HttpOnly Flag
                            break;

                        case "Cross-Site Scripting/DOM":
                        case "Cross-Site Scripting/Persistent":
                        case "Cross-Site Scripting/Reflected":
                            ruleCweMap.put(ruleId, CweNumber.XSS);
                            break;
                        case "Cross-Site Scripting/Poor Validation":
                            ruleCweMap.put(ruleId, 20); // CWE-20 Improper Input Validation
                            break;

                        case "Denial of Service/Format String":
                        case "Denial of Service/StringBuilder":
                            ruleCweMap.put(
                                    ruleId, 400); // CWE-400 Uncontrolled Resource Consumption
                            break;

                        case "Header Manipulation/Cookies":
                            ruleCweMap.put(ruleId, 113); // CWE-113 HTTP Resp. Splitting
                            break;

                        case "J2EE Bad Practices/getConnection()":
                            ruleCweMap.put(
                                    ruleId,
                                    245); // CWE-245 J2EE Bad Pract: Direct Mgt of Connections
                            break;

                        case "J2EE Misconfiguration/Missing Error Handling":
                        case "System Information Leak/External":
                        case "System Information Leak/Internal":
                        case "System Information Leak/Incomplete Servlet Error Handling":
                            ruleCweMap.put(
                                    ruleId, 209); // CWE-209 Generation of Err Msg w/Sensitive Info
                            break;

                        case "Password Management/Empty Password":
                        case "Password Management/Empty Password in Configuration File":
                            ruleCweMap.put(ruleId, 521); // CWE-521 Weak Password
                            break;
                        case "Password Management/Hardcoded Password":
                            ruleCweMap.put(ruleId, 798); // CWE-798 Hard-coded credentials
                            break;
                        case "Password Management/Password in Configuration File":
                            ruleCweMap.put(ruleId, 256); // CWE-256 Plaintext storage of pwd
                            break;

                        case "Privacy Violation/Shoulder Surfing":
                            ruleCweMap.put(ruleId, 549); // CWE-549 Missing Password Field Masking
                            break;

                        case "SQL Injection/Hibernate":
                            ruleCweMap.put(ruleId, 564); // CWE-564 SQLi: Hibernate
                            break;

                        case "Weak Cryptographic Hash/User-Controlled Algorithm":
                            ruleCweMap.put(ruleId, CweNumber.WEAK_HASH_ALGO);
                            break;

                        case "Weak Encryption/Insecure Mode of Operation":
                            ruleCweMap.put(ruleId, 326); // CWE-326 Inadequate Encryption Strength
                            break;

                        case "Weak Encryption/Missing Required Step":
                            ruleCweMap.put(ruleId, 325); // CWE-325 Missing Cryptographic Step
                            break;

                        default:
                            // Then we try to get the mapping from existing FortifyReader
                            int cwe = FortifyReader.cweLookup(ruleName, "", null);
                            if (cwe != CweNumber.UNMAPPED) {
                                ruleCweMap.put(ruleId, cwe);
                            }
                    }
                } catch (JSONException e) {
                    // Do nothing if the rule name can't be found as there are a bunch of id's at
                    // the end of the file that aren't related to rules. e.g.,
                    // {
                    //   "id": "23311ABB-0992-43C8-91A2-22F474402E63",
                    //   "guid": "23311abb-0992-43c8-91a2-22f474402e63"
                    // },
                    // {
                    //   "id": "2918B097-371F-4EE9-90F7-477F18065F73",
                    //   "guid": "2918b097-371f-4ee9-90f7-477f18065f73"
                    // }, ...
                }
            }
        } catch (JSONException e) {
            // This error should never happen.
            System.out.println(
                    "Error parsing rules block in Fortify SARIF file to generate CWE mapping for ruleIds.");
            e.printStackTrace();
        }

        return ruleCweMap;
    }
}
