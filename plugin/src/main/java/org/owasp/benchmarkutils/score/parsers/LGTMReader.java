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

import java.util.HashMap;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class LGTMReader extends Reader {

    private final String LGTMCWEPREFIX = "external/cwe/cwe-";
    private final int LGTMCWEPREFIXLENGTH = LGTMCWEPREFIX.length();

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.filename().endsWith(".sarif")
                    && resultFile.isJson()
                    && resultFile
                            .json()
                            .getJSONArray("runs")
                            .getJSONObject(0)
                            .getJSONObject("properties")
                            .has("semmle.sourceLanguage");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        /*
         * This parser was written against version 2.1.0 of the sarif-schema
         * NOTE: To help understand contents of JSON file, use: http://jsonviewer.stack.hu to view it.
         */
        //		String resultsFormatVersion = obj.getString( "version" ); // Might be needed in future
        // if format changes

        JSONArray runs = resultFile.json().getJSONArray("runs");

        TestSuiteResults tr = new TestSuiteResults("LGTM", true, TestSuiteResults.ToolType.SAST);
        // Scan time is not included in the sarif-schema. But scan time is provided on their web
        // site next to results
        tr.setTime(resultFile.file()); // This grabs the scan time out of the filename, if provided
        // e.g., Benchmark_1.2_LGTM-660.sarif, means the scan took 660 seconds.

        for (int i = 0; i < runs.length(); i++) {
            // There are 1 or more runs in each results file, one per language found (Java,
            // JavaScript, etc.)
            JSONObject run = runs.getJSONObject(i);
            JSONObject properties = run.getJSONObject("properties");
            String sourceLang = properties.getString("semmle.sourceLanguage");

            // Only consider the Java results
            if ("java".equalsIgnoreCase(sourceLang)) {

                // First, set the version of LGTM used to do the scan
                JSONObject driver = run.getJSONObject("tool").getJSONObject("driver");
                tr.setToolVersion(driver.getString("version"));

                // Then, identify all the rules that report results and which CWEs they map to
                JSONArray rules = driver.getJSONArray("rules");
                // System.out.println("Found: " + rules.length() + " rules.");
                HashMap<String, Integer> rulesUsed = parseLGTMRules(rules);
                // System.out.println("Parsed: " + rulesUsed.size() + " rules.");

                // Finally, parse out all the results
                JSONArray results = run.getJSONArray("results");
                // System.out.println("Found: " + results.length() + " results.");

                for (int j = 0; j < results.length(); j++) {
                    TestCaseResult tcr =
                            parseLGTMFinding(results.getJSONObject(j), rulesUsed); // , version );
                    if (tcr != null) {
                        tr.put(tcr);
                    }
                }
            }
        }

        return tr;
    }

    private HashMap<String, Integer> parseLGTMRules(JSONArray rulesJSON) {
        HashMap<String, Integer> rulesUsed = new HashMap<String, Integer>();

        for (int j = 0; j < rulesJSON.length(); j++) {
            JSONObject ruleJSON = rulesJSON.getJSONObject(j);

            try {
                String ruleName = ruleJSON.getString("name");
                JSONArray tags = ruleJSON.getJSONObject("properties").getJSONArray("tags");
                for (int i = 0; i < tags.length(); i++) {
                    String val = tags.getString(i);
                    if (val.startsWith(LGTMCWEPREFIX)) {
                        //						System.out.println("Rule found for CWE: " +
                        // Integer.parseInt(val.substring(LGTMCWEPREFIXLENGTH)));
                        //						int cwe = fixCWE( cweNumber );
                        rulesUsed.put(
                                ruleName, Integer.parseInt(val.substring(LGTMCWEPREFIXLENGTH)));
                        break; // Break out of for loop because we only want to use the first CWE it
                        // is mapped to
                        // currently. If they add rules where the first CWE is not the preferred
                        // one, then we need
                        // to implement fixCWE() and invoke it (commented out example below)
                    }
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return rulesUsed;
    }

    private TestCaseResult parseLGTMFinding(
            JSONObject finding, HashMap<String, Integer> rulesUsed) {
        try {
            TestCaseResult tcr = new TestCaseResult();
            String filename = null;
            JSONArray locations = finding.getJSONArray("locations");
            filename =
                    locations
                            .getJSONObject(0)
                            .getJSONObject("physicalLocation")
                            .getJSONObject("artifactLocation")
                            .getString("uri");
            filename = filename.substring(filename.lastIndexOf('/'));
            if (filename.contains(BenchmarkScore.TESTCASENAME)) {
                tcr.setNumber(testNumber(filename));
                String ruleId = finding.getString("ruleId");
                Integer cweForRule = rulesUsed.get(ruleId);
                //				System.out.println("Found finding in: " + testNumber + " of type: " + ruleId +
                // " CWE: " + cweForRule);
                if (cweForRule == null) {
                    return null;
                }
                if (locations.length() > 1) {
                    System.out.println(
                            "Unexpectedly found more than one location for finding against rule: "
                                    + ruleId);
                }
                int cwe = cweForRule.intValue();
                tcr.setCWE(cwe);
                //				tcr.setCategory( props.getString( "subcategoryShortDescription" ) ); //
                // Couldn't find any Category info in results file
                tcr.setEvidence(finding.getJSONObject("message").getString("text"));
            }
            return tcr;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /*
    	private int fixCWE( String cweNumber ) {
    		int cwe = Integer.parseInt( cweNumber );
    		if ( cwe == 94 ) cwe = 643;
    		if ( cwe == 36 ) cwe = 22;
    		if ( cwe == 23 ) cwe = 22;
    		return cwe;
    	}
    */
}
