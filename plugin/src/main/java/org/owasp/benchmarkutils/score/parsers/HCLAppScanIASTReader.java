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

import java.io.BufferedReader;
import java.io.File;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.StringUtils;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class HCLAppScanIASTReader extends Reader {

    public static void main(String[] args) throws Exception {
        File f = new File("results/HCL-IAST.hcl");
        ResultFile resultFile = new ResultFile(f);
        HCLAppScanIASTReader cr = new HCLAppScanIASTReader();
        cr.parse(resultFile);
    }

    public HCLAppScanIASTReader() {
        createVulnerabilitiesMap();
    }

    private Map<String, Integer> vulnerabilityToCweNumber;

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".hcl");
    }

    private void createVulnerabilitiesMap() {
        vulnerabilityToCweNumber = new HashMap<>();
        vulnerabilityToCweNumber.put("attRespCookieNotSecureSSL", CweNumber.INSECURE_COOKIE);
        vulnerabilityToCweNumber.put("SessionManagement.Cookies", CweNumber.INSECURE_COOKIE);
        vulnerabilityToCweNumber.put("Injection.SQL", CweNumber.SQL_INJECTION);
        vulnerabilityToCweNumber.put("Injection.OS", CweNumber.COMMAND_INJECTION);
        vulnerabilityToCweNumber.put("Injection.LDAP", CweNumber.LDAP_INJECTION);
        vulnerabilityToCweNumber.put("CrossSiteScripting.Reflected", CweNumber.XSS);
        vulnerabilityToCweNumber.put("Injection.XPath", CweNumber.XPATH_INJECTION);
        vulnerabilityToCweNumber.put("PathTraversal", CweNumber.PATH_TRAVERSAL);
        vulnerabilityToCweNumber.put("Cryptography.InsecureAlgorithm", CweNumber.WEAK_HASH_ALGO);
        vulnerabilityToCweNumber.put("Cryptography.Mac", CweNumber.WEAK_HASH_ALGO);
        vulnerabilityToCweNumber.put("Cryptography.WeakHash", CweNumber.WEAK_HASH_ALGO);
        vulnerabilityToCweNumber.put("Cryptography.PoorEntropy", CweNumber.WEAK_RANDOM);
        vulnerabilityToCweNumber.put("Cryptography.NonStandard", CweNumber.WEAK_CRYPTO_ALGO);
        vulnerabilityToCweNumber.put("Cryptography.Ciphers", CweNumber.WEAK_CRYPTO_ALGO);
        vulnerabilityToCweNumber.put("Validation.Required", CweNumber.TRUST_BOUNDARY_VIOLATION);
        vulnerabilityToCweNumber.put("TrustBoundaryViolation", CweNumber.TRUST_BOUNDARY_VIOLATION);
        vulnerabilityToCweNumber.put("attLoginNotOverSSL", CweNumber.UNPROTECTED_CREDENTIALS_TRANSPORT);
        vulnerabilityToCweNumber.put("attFileUploadXXE", CweNumber.XXE);
        vulnerabilityToCweNumber.put("attCrossSiteRequestForgery", CweNumber.CSRF);
        vulnerabilityToCweNumber.put("passParamGET", CweNumber.UNPROTECTED_CREDENTIALS_TRANSPORT);
        vulnerabilityToCweNumber.put("attJavaDeserCodeExec", CweNumber.COMMAND_INJECTION);
        vulnerabilityToCweNumber.put("GV_JSONXSS", CweNumber.XSS);
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("HCL AppScan IAST", true, TestSuiteResults.ToolType.IAST);

        BufferedReader reader = new BufferedReader(new StringReader(resultFile.content()));
        String FIRSTLINEINDICATOR =
                BenchmarkScore.TESTCASENAME
                        + StringUtils.repeat("0", BenchmarkScore.TESTIDLENGTH - 1)
                        + "1";
        String firstLine = null;
        String lastLine = "";
        String line = "";
        tr.setToolVersion("1.0");
        while (line != null) {
            try {
                line = reader.readLine();
                if (line != null) {
                    if (line.contains("writeVulnerabilityToFile")) {
                        parseFindings(tr, line);
                    } else if (line.contains("Loading agent")) {
                        String version = line.split("Loading agent ")[1];
                        tr.setToolVersion(version.trim());
                    } else if (line.contains("[checking URL:")
                            && line.contains(FIRSTLINEINDICATOR)) {
                        firstLine = line;
                    } else if (line.contains("[checking URL:")) {
                        lastLine = line;
                    }
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
        reader.close();
        tr.setTime(calculateTime(firstLine, lastLine));
        return tr;
    }

    private void parseFindings(TestSuiteResults tr, String json) throws Exception {
        TestCaseResult tcr = new TestCaseResult();

        try {
            String splitJson = json.substring(json.indexOf("{"));
            JSONObject obj = new JSONObject(splitJson);
            JSONObject result = obj.getJSONArray("issue-group").getJSONObject(0);

            String ruleId = result.getJSONObject("issue-type").getString("ref");
            tcr.setCWE(cweLookup(ruleId));
            tcr.setCategory(ruleId);

            JSONObject request =
                    result.getJSONArray("variant-group").getJSONObject(0).getJSONObject("request");
            String uri = request.getString("uri");

            if (uri.contains(BenchmarkScore.TESTCASENAME)) {
                tcr.setNumber(testNumber(uri));
                if (tcr.getCWE() != 0) {
                    // System.out.println( tcr.getNumber() + "\t" + tcr.getCWE() + "\t" +
                    // tcr.getCategory() );
                    tr.put(tcr);
                }
            }
        } catch (Exception e) {
            // System.err.println("> Parse error: " + json);
            // e.printStackTrace();
        }
    }

    private int cweLookup(String rule) {
        Integer cweNumber = vulnerabilityToCweNumber.get(rule);
        if (cweNumber == null) {
            System.out.println("WARNING: HCL AppScan IAST-Unrecognized finding type: " + rule);
            return 0;
        }
        return cweNumber;
    }

    private String calculateTime(String firstLine, String lastLine) {
        try {
            String start = firstLine.split(" \\[")[0];
            String stop = lastLine.split(" \\[")[0];
            SimpleDateFormat dateAndTimeParser = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS");
            SimpleDateFormat timeParser = new SimpleDateFormat("HH:mm:ss.SSS");
            Date startTime;
            Date stopTime;
            try {
                // try parse date and time
                startTime = dateAndTimeParser.parse(start);
                stopTime = dateAndTimeParser.parse(stop);
            } catch (ParseException e) {
                // try parse time only (for older versions)
                startTime = timeParser.parse(start);
                stopTime = timeParser.parse(stop);
            }
            long startMillis = startTime.getTime();
            long stopMillis = stopTime.getTime();
            long seconds = (stopMillis - startMillis) / 1000;
            return seconds + " seconds";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}
