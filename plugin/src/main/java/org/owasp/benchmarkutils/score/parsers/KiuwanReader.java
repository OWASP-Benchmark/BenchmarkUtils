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

public class KiuwanReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".threadfix");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        /*
         * This parser was written against the .threadfix schema as defined here:
         * https://denimgroup.atlassian.net/wiki/spaces/TDOC/pages/496009270/ThreadFix+File+Format
         *
         * To make any JSON file more readable: python -m json.tool file.json > prettyjson.txt
         */
        JSONObject obj = resultFile.json();
        //		String resultsFormatVersion = obj.getString( "version" ); // Note: no threadfix version
        // info included in format.

        JSONArray findings = obj.getJSONArray("findings");
        JSONObject metadata = obj.getJSONObject("metadata");

        String source = obj.getString("source");

        TestSuiteResults tr = new TestSuiteResults(source, true, TestSuiteResults.ToolType.SAST);

        // Scan time is included in the threadfix schema: "metadata/Kiuwan-AnalysisDuration"
        if (null != metadata) {
            String analysisDuration = metadata.getString("Kiuwan-AnalysisDuration");
            if (null != analysisDuration) {
                tr.setTime(analysisDuration);
            }
        }

        // Set the version of Kiuwan used to do the scan: "metadata/Kiuwan-EngineVersion"
        if (null != metadata) {
            String engineVersion = metadata.getString("Kiuwan-EngineVersion");
            if (null != engineVersion) {
                tr.setToolVersion(engineVersion);
            }
        }

        // System.out.println("Found: " + findings.length() + " findings.");
        for (int i = 0; i < findings.length(); i++) {
            JSONObject finding = findings.getJSONObject(i);

            TestCaseResult tcr = parseKiuwanFinding(finding);
            if (tcr != null) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    private TestCaseResult parseKiuwanFinding(JSONObject finding) {
        try {
            TestCaseResult tcr = new TestCaseResult();
            JSONObject staticDetails = finding.getJSONObject("staticDetails");
            JSONArray dataFlow = staticDetails.getJSONArray("dataFlow");
            int propagationPathLength = dataFlow.length() - 1;
            String filename = dataFlow.getJSONObject(propagationPathLength).getString("file");
            filename = filename.substring(filename.lastIndexOf('/'));
            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                tcr.setNumber(testNumber(filename));

                int cwe = -1;
                try {
                    JSONArray mappings = finding.getJSONArray("mappings");
                    for (int i = 0; i < mappings.length(); i++) {
                        String val = mappings.getJSONObject(i).getString("mappingType");
                        if (val.equalsIgnoreCase("CWE")) {
                            // fixCWE maps the supplied CWE to the one we use, if necessary
                            cwe = fixCWE(mappings.getJSONObject(i).getString("value"));
                            break;
                        }
                    }

                    if (cwe != -1) {
                        tcr.setCWE(cwe);
                        tcr.setCategory(finding.getString("summary"));
                        tcr.setEvidence(finding.getString("scannerDetail"));
                        return tcr;
                    }

                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private int fixCWE(String cweNumber) {
        int cwe = Integer.parseInt(cweNumber);

        if (cwe == 564) {
            cwe = CweNumber.SQL_INJECTION;
        }

        if (cwe == 77) {
            cwe = CweNumber.COMMAND_INJECTION;
        }
        return cwe;
    }
}
