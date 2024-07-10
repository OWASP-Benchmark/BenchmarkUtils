package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.*;

public class GitLabSastReader extends Reader {
    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.json().has("scan")
                && resultFile
                .json()
                .getJSONObject("scan")
                .getJSONObject("analyzer")
                .getJSONObject("vendor")
                .getString("name")
                .equalsIgnoreCase("GitLab");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("GitLab-SAST", true, TestSuiteResults.ToolType.SAST);

        JSONArray vulnerabilities = resultFile.json().getJSONArray("vulnerabilities");

        for (int vulnerability = 0; vulnerability < vulnerabilities.length(); vulnerability++) {
            TestCaseResult tcr = parseGitLabSastFindings(vulnerabilities.getJSONObject(vulnerability));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private TestCaseResult parseGitLabSastFindings(JSONObject vulnerability) {

        try {
            String className = vulnerability.getJSONObject("location").getString("file");
            className = (className.substring(className.lastIndexOf('/') + 1)).split("\\.")[0];

            if (className.startsWith(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();

                JSONArray identifiers = vulnerability.getJSONArray("identifiers");

                int cwe = identifiers.getJSONObject(1).getInt("value");
                cwe = translate(cwe);

                String category = identifiers.getJSONObject(2).getString("name");
                category = category.split("-")[1].strip();

                String evidence = vulnerability.getString("cve");

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

    private int translate(int cwe) {
        //in gitlab sast {
        //  "trustbound": 306,  // Authentication Bypass Using Trust Boundaries (CWE-306)
        //  "weakrand": 338,  // Use of Cryptographically Weak Pseudo-Random Number Generator (CWE-338)
        //  "sqli": 89,  // SQL Injection (CWE-89)
        //  "crypto": 327,  // Use of a Broken or Risky Cryptographic Algorithm (CWE-327)
        //  "cmdi": 185,  // Improper Control of Generation of Code ('Code Injection') (CWE-185)
        //  "xss": 79,  // Cross-site Scripting (CWE-79)
        //  "hash": 326,  // Inadequate Encryption Strength (CWE-326)
        //  "pathtraver": 22,  // Path Traversal (CWE-22)
        //  "securecookie": 614,  // Sensitive Cookie in HTTPS Session Without 'Secure' Attribute (CWE-614)
        //  "xpathi": 643,  // XPath Injection (CWE-643)
        //  "ldapi": 90,  // Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') (CWE-90)
        //  "httpresponse": 113,  // Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response Splitting') (CWE-113)
        //  "debugcode": 259,  // Use of Hard-coded Password (CWE-259)
        //  "cryptointegration": 1004  // Sensitive Cookie Without 'HttpOnly' Flag (CWE-1004)
        //}

        //in benchmark tool {
        //  "trustbound": 501,
        //  "weakrand": 330,
        //  "sqli": 89,
        //  "crypto": 327,
        //  "cmdi": 78,
        //  "xss": 79,
        //  "hash": 328,
        //  "pathtraver": 22,
        //  "securecookie": 614,
        //  "xpathi": 643,
        //  "ldapi": 90
        //}
        switch (cwe) {
            case 22:
                return CweNumber.PATH_TRAVERSAL;
            case 79:
                return CweNumber.XSS;
            case 89:
                return CweNumber.SQL_INJECTION;
            case 90:
                return CweNumber.LDAP_INJECTION;
            case 113:
                return CweNumber.HTTP_RESPONSE_SPLITTING;
            case 185:
                return CweNumber.COMMAND_INJECTION;
            case 326:
            case 327:
            case 328:
                return CweNumber.WEAK_CRYPTO_ALGO;
            case 338:
                return CweNumber.WEAK_RANDOM;
            case 614:
                return CweNumber.INSECURE_COOKIE;
            case 643:
                return CweNumber.XPATH_INJECTION;
            case 1004:
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;
            case 259:
            case 306:
                break;
            default:
                System.out.println(
                        "INFO: Found following CWE in GitLab SAST results which we haven't seen before: "
                                + cwe);
        }

        return cwe;
    }
}
