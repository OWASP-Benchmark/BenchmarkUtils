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
 * @author Nuno Oliveira
 * @created 2019
 */
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class CheckmarxESReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".json")
                && resultFile.line(1).contains("Vendor")
                && resultFile.line(1).contains("Checkmarx");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Checkmarx SAST", true, TestSuiteResults.ToolType.SAST);

        JSONObject obj = resultFile.json();

        // engine version
        String version = obj.getString("EngineVersion");
        String[] parts = version.split("\\.");
        version = parts[0] + "." + parts[1] + "." + parts[2];
        tr.setToolVersion(version);

        // duration time
        tr.setTime(obj.getString("ScanDuration"));

        String key = "Queries";
        JSONArray queries = obj.getJSONArray(key);

        for (int i = 0; i < queries.length(); i++) {
            JSONObject query = queries.getJSONObject(i);

            // cwe
            int cwe = query.getJSONObject("Metadata").getInt("CweId");
            try {
                cwe = translate(cwe);
            } catch (NumberFormatException ex) {
                System.out.println("flaw: " + query);
            }

            // category
            String category = query.getJSONObject("Metadata").getString("QueryName");
            if (isIrrelevant(category)) {
                continue;
            }

            // evidence
            String evidence = category;

            // get tcr for each result
            JSONArray results = query.getJSONArray("Results");
            for (int j = 0; j < results.length(); j++) {
                TestCaseResult tcr =
                        parseCheckmarxFindings(cwe, category, evidence, results.getJSONObject(j));
                if (tcr != null) {
                    tr.put(tcr);
                }
            }
        }

        return tr;
    }

    private boolean isIrrelevant(String name) {
        return name.equals("Dynamic_SQL_Queries")
                || name.equals("Heuristic_2nd_Order_SQL_Injection")
                || name.equals("Heuristic_SQL_Injection")
                || name.equals("Second_Order_SQL_Injection")
                || name.equals("Blind_SQL_Injections")
                || name.equals("Improper_Build_Of_Sql_Mapping")
                || name.equals("SQL_Injection_Evasion_Attack")
                || name.equals("Potential_SQL_Injection")
                || name.equals("Client_Side_Injection")
                || name.equals("GWT_DOM_XSS")
                || name.equals("GWT_Reflected_XSS")
                || name.equals("Heuristic_CGI_Stored_XSS")
                || name.equals("Heuristic_Stored_XSS")
                || name.equals("Stored_XSS")
                || name.equals("Suspected_XSS")
                || name.equals("UTF7_XSS")
                || name.equals("CGI_Stored_XSS")
                || name.equals("Potential_GWT_Reflected_XSS")
                || name.equals("Potential_I_Reflected_XSS_All_Clients")
                || name.equals("Potential_IO_Reflected_XSS_All_Clients")
                || name.equals("Potential_O_Reflected_XSS_All_ClientsS")
                || name.equals("Potential_Stored_XSS")
                || name.equals("Potential_UTF7_XSS")
                || name.equals("Stored_Command_Injection")
                || name.equals("CGI_Reflected_XSS_All_Clients")
                || name.equals("Unprotected_Cookie");
    }

    private int translate(int cwe) {
        switch (cwe) {
            case 77:
            case 15:
                return CweNumber.COMMAND_INJECTION;
            case 36:
            case 23:
                return CweNumber.PATH_TRAVERSAL;
            case 338:
                return CweNumber.WEAK_RANDOM;
        }
        return cwe;
    }

    private TestCaseResult parseCheckmarxFindings(
            int cwe, String category, String evidence, JSONObject result) {
        try {
            TestCaseResult tcr = new TestCaseResult();
            tcr.setCWE(cwe);
            tcr.setCategory(category);
            tcr.setEvidence(evidence);

            // get the testcase number
            // Try get testcase from the first node
            JSONArray nodes = result.getJSONArray("Nodes");
            String resultFileName = nodes.getJSONObject(0).getString("FileName");
            String testcaseName = resultFileName.substring(resultFileName.lastIndexOf('\\') + 1);
            if (testcaseName.startsWith(BenchmarkScore.TESTCASENAME)) {
                String testNo =
                        testcaseName.substring(
                                BenchmarkScore.TESTCASENAME.length(),
                                testcaseName.lastIndexOf('.'));
                try {
                    tcr.setNumber(Integer.parseInt(testNo));
                } catch (NumberFormatException e) {
                    e.printStackTrace();
                }

                return tcr;
            } else {
                resultFileName = nodes.getJSONObject(nodes.length() - 1).getString("FileName");
                testcaseName = resultFileName.substring(resultFileName.lastIndexOf('\\') + 1);
                if (testcaseName.startsWith(BenchmarkScore.TESTCASENAME)) {
                    String testNo =
                            testcaseName.substring(
                                    BenchmarkScore.TESTCASENAME.length(),
                                    testcaseName.lastIndexOf('.'));
                    try {
                        tcr.setNumber(Integer.parseInt(testNo));
                    } catch (NumberFormatException e) {
                        e.printStackTrace();
                    }
                    return tcr;
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
