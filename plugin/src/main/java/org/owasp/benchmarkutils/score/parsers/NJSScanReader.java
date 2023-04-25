/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see https://owasp.org/www-project-benchmark
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details
 *
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

/**
 * Class with methods to read from the results of njsscan and place them in the conforming
 * TestSuiteResults. See: https://github.com/ajinabraham/njsscan
 */
public class NJSScanReader extends Reader {

    /**
     * Searches for the key "njsscan_version" in the given json object
     *
     * @param resultFile The result file to search the key for
     * @return True if "njsscan_version" is present, false otherwise
     */
    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.isJson() && resultFile.json().has("njsscan_version");
        } catch (JSONException jsonE) {
            return false;
        }
    }

    /**
     * Parse the JSONObject and return test results. Before using this parser, it should be checked
     * that the JSONObject supplied is a njsscan report using the function
     * NJSScanReader.isNJSScanReport(json)
     *
     * @param resultFile The ResultFile containing the JSONObject generated from a njsscan report
     * @return A TestSuiteResults object containing a mapping of test cases
     */
    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        JSONObject cwe_object;

        TestSuiteResults tsrs =
                new TestSuiteResults("njsscan", false, TestSuiteResults.ToolType.SAST);

        try {
            // "njsscan_version" holds the version of the program
            String njsscan_version = resultFile.json().getString("njsscan_version");
            tsrs.setToolVersion(njsscan_version);

            // "nodejs" holds a dictionary of all the encountered cwes
            cwe_object = resultFile.json().getJSONObject("nodejs");
            String[] cwes = JSONObject.getNames(cwe_object);

            // Iterate through all CWEs and process them
            for (String cwe : cwes) {
                TestCaseResult[] results = null;
                results = parseCWE(cwe_object.getJSONObject(cwe));

                if (results != null) {
                    // Place each result in the full results mapping
                    for (TestCaseResult tcr : results) {
                        tsrs.put(tcr);
                    }
                }
            }
        } catch (JSONException jsonE) {
            // To standard out
            System.out.println("Error in parsing JSONObject: " + jsonE.toString());
            // To standard err
            jsonE.printStackTrace();
            return null;
        }

        return tsrs;
    }

    /*Example JSON output:
     * {
     *   "errors": [],
     *   "njsscan_version": "0.2.8",
     *   "nodejs": {
     *     "generic_error_disclosure": {
     *       "files": [
     *         {
     *           "file_path": "index.js",
     *           "match_lines": [112, 116],
     *           "match_position": [3, 4],
     *           "match_string": "} catch (error) {\n\tconsole.error(error)\n}"
     *         }
     *       ],
     *       "metadata": {
     *         "cwe": "CWE-209: Generation of Error Message Containing Sensitive Information",
     *         "description": "Error messages with stack traces may expose sensitive information about the application.",
     *         "owasp": "A3: Sensitive Data Exposure",
     *         "severity": "WARNING"
     *       }
     *     }
     *   }
     * }
     *
     * Under "nodejs" is a dictionary which contains the CWEs with an assigned name by the program.
     * Each CWE is also an object which contains the keys "files" and "metadata". Under "metadata", the
     * associated CWE number can be found.
     *
     * Each found vulnerability is grouped by CWE. One CWE contains a JSON array of all the files
     * which were identified to have the CWE.
     * A single file is a JSON object which contains the file path (relative to the call), the lines in
     * the file matched, and the string where it was found.
     */

    /**
     * Parses a CWE JSONObject and returns test case results for the files that were identified to
     * have the CWE. See example JSON in the comment above.
     *
     * @param issue The JSONObject which contains the "files" and "metadata" key
     * @return Array of TestCaseResult all for the same CWE
     */
    private TestCaseResult[] parseCWE(JSONObject CWE) {
        List<TestCaseResult> results = new ArrayList<TestCaseResult>();

        try {
            JSONObject metadata = CWE.getJSONObject("metadata");
            String cwe_str = metadata.getString("cwe");

            // Grab the number between "-num:"
            cwe_str = cwe_str.substring(cwe_str.indexOf('-') + 1, cwe_str.indexOf(':'));
            int cwe_identifier = cweLookup(Integer.parseInt(cwe_str));

            // Process each file
            JSONArray file_arr = CWE.getJSONArray("files");
            for (int i = 0; i < file_arr.length(); i++) {
                TestCaseResult result =
                        produceTestCaseResult(file_arr.getJSONObject(i), cwe_identifier);
                if (result != null) results.add(result);
            }

            // Returns the result as an array, the new array
            // created is only for toArray to determine type
            return results.toArray(new TestCaseResult[0]);

        } catch (JSONException jsonE) {
            System.out.println("Unable to parse the CWE: " + jsonE.toString()); // To std.out
            jsonE.printStackTrace(); // To std.err
        } catch (Exception e) {
            System.out.println(
                    "Issue with parsing the identifier, either substring or parseint fail: "
                            + e.toString());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Parses a single File JSONObject as shown in the example JSON (entry from the array from
     * "files"). This should have keys "file_path", "match_line", "match_position", and
     * "match_string"
     *
     * <p>Catch errors here because I do not want to interrupt the for loop in the above call
     *
     * @param file The JSONObject which contains a single file dictionary object
     * @param cwe_identifier The numerical value of the CWE
     * @return A TestCaseResult with the information from the file or null if finding is not in a
     *     test case source file
     */
    private TestCaseResult produceTestCaseResult(JSONObject file, int cwe_identifier) {
        TestCaseResult tcr = new TestCaseResult();
        tcr.setCWE(cwe_identifier);

        String filename = "";
        try {
            filename = file.getString("file_path");
            if (!filename.contains(BenchmarkScore.TESTCASENAME)) return null;

            // This converts the string to a path, then uses the built in path function
            // to get the file name only (system independent!). Then, I strip out all non-numbers
            // Will break if it's decided other numbers should belong in the name, ex:
            // BenchmarkTestv2.00001.java
            // Consider a utility function that can be used across all of the parsers to extract the
            // number. This way, if changes are done they only need to be done in one place
            // filename = Paths.get(filename).getFileName().toString();
            // filename = filename.replaceAll("[^0-9]", "");

            // Note: This code should be checked with test cases
            tcr.setNumber(testNumber(filename));

        } catch (JSONException jsonE) {
            System.out.println("Issue with file JSON : " + jsonE.toString());
            jsonE.printStackTrace();
        } catch (NumberFormatException nfe) {
            System.out.println(
                    "Unable to parseint: " + nfe.toString() + " from filename: '" + filename + "'");
            nfe.printStackTrace();
        }

        return tcr;
    }

    private int cweLookup(int cwe) {
        switch (cwe) {
            case 23: // Relative Path Traversal <-- care about this one
                return 22; // We expect 22, not 23

            case 79: // XSS <-- care about this one
            case 209: // Info leak from Error Message
            case 400: // Uncontrolled Resource Consumption
            case 522: // Insufficiently protected credentials
            case 613: // Insufficient session expiration
            case 614: // Sensitive cookie without Secure Attribute <-- care about this one
            case 693: // Protection Mechanism Failure (e.g., One or more Security Response header is
                // explicitly disabled in Helmet)
            case 798: // Hard coded credentials
            case 1275: // Sensitive cookie w/ Improper SameSite Attribute
                break; // Don't care about these, or mapping is correct, so return 'as is'.

            case 943: // Improper Neutralization of Special Elements in Data Query Logic (Child of
                // SQL Injection)
                return 89; // This is likely an SQLi finding, so mapping to that.

            default:
                System.out.println(
                        "WARNING: NJSScan-Unrecognized cwe: "
                                + cwe
                                + ". Verify mapping is correct and add mapping to NJSScanReader.");
        }

        return cwe;
    }
}
