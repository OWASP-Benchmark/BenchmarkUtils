package org.owasp.benchmarkutils.score.parsers;

import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SnykReader extends Reader {

    public static final int INVALID_RULE_ID = -1;
    private static final Map<String, Integer> snykCweMap =
            new HashMap<String, Integer>() {
                {
                    put("Xpath", CweNumber.XPATH_INJECTION);
                    put("WebCookieWithSecureFalse", CweNumber.INSECURE_COOKIE);
                    put("Sqli", CweNumber.SQL_INJECTION);
                    put("PT", CweNumber.PATH_TRAVERSAL);
                    put("HardcodedPassword", 0);
                    put("WebCookieMissesCallToSetHttpOnly", CweNumber.COOKIE_WITHOUT_HTTPONLY);
                    put("ServerInformationExposure", 0);
                    put("UserControlledFormatString", CweNumber.EXTERNALLY_CONTROLLED_STRING);
                    put("SpringCSRF", CweNumber.CSRF);
                    put("TrustBoundaryViolation", CweNumber.TRUST_BOUNDARY_VIOLATION);
                    put("CommandInjection", CweNumber.COMMAND_INJECTION);
                    put("EnvCommandInjection", CweNumber.COMMAND_INJECTION);
                    put("DOMXSS", CweNumber.XSS);
                    put("XSS", CweNumber.XSS);
                    put("InsecureCipherNoIntegrity", CweNumber.WEAK_CRYPTO_ALGO);
                    put("InsecureDefaultAesCipher", CweNumber.WEAK_CRYPTO_ALGO);
                    put("HttpResponseSplitting", CweNumber.HTTP_RESPONSE_SPLITTING);
                    put("InsecureSecret", CweNumber.WEAK_RANDOM);
                    put("LdapInjection", CweNumber.LDAP_INJECTION);
                    put("InsecureCipher", CweNumber.WEAK_CRYPTO_ALGO);
                    put("InsecureHash", CweNumber.WEAK_HASH_ALGO);
                }
            };

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson() && isSnyk(resultFile);
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Snyk", true, TestSuiteResults.ToolType.SAST);

        JSONArray results =
                resultFile.json().getJSONArray("runs").getJSONObject(0).getJSONArray("results");

        for (int result = 0; result < results.length(); result++) {
            TestCaseResult tcr = parseSnykFindings(results.getJSONObject(result));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private TestCaseResult parseSnykFindings(JSONObject result) {
        try {
            String className =
                    result.getJSONArray("locations")
                            .getJSONObject(0)
                            .getJSONObject("physicalLocation")
                            .getJSONObject("artifactLocation")
                            .getString("uri");
            className = (className.substring(className.lastIndexOf('/') + 1)).split("\\.")[0];
            if (className.startsWith(BenchmarkScore.TESTCASENAME)) {

                TestCaseResult tcr = new TestCaseResult();

                String ruleId = result.getString("ruleId");
                ruleId = (ruleId.substring(ruleId.lastIndexOf('/') + 1)).split("\\.")[0];

                int cwe = snykCweMap.getOrDefault(ruleId, INVALID_RULE_ID);

                if (cwe == INVALID_RULE_ID) {
                    System.out.println("CWE # not parseable from: " + ruleId);
                    return null;
                }

                String evidence = result.getJSONObject("message").getString("text");

                tcr.setCWE(cwe);
                tcr.setCategory(ruleId);
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

    private Boolean isSnyk(ResultFile resultFile) {

        try {
            return resultFile
                    .json()
                    .getJSONArray("runs")
                    .getJSONObject(0)
                    .getJSONObject("tool")
                    .getJSONObject("driver")
                    .getString("name")
                    .equalsIgnoreCase("SnykCode");
        } catch (JSONException e) {
            return false;
        }
    }
}
