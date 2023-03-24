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
import java.io.FileReader;
import java.text.SimpleDateFormat;
import java.util.Date;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ContrastAssessReader extends Reader {

    private final String NODEFINDINGLINEINDICATOR = "contrast:rules:sinks - ";
    private final String NODEAGENTVERSIONLINEINDICATOR = "contrast:contrast-init - agent v";

    public static void main(String[] args) throws Exception {
        File f = new File("results/Benchmark_1.2-Contrast.log");
        ResultFile resultFile = new ResultFile(f);
        ContrastAssessReader cr = new ContrastAssessReader();
        cr.parse(resultFile);
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        // first line contains: Starting Contrast (for Java) or contrast:contrastAgent (for Node)
        return resultFile.filename().endsWith(".log")
                && resultFile.line(0).toLowerCase().contains(" contrast");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Contrast Assess", true, TestSuiteResults.ToolType.IAST);

        BufferedReader reader = new BufferedReader(new FileReader(resultFile.file()));
        String FIRSTLINEINDICATOR = BenchmarkScore.TESTCASENAME;
        String firstLine = null;
        String lastLine = "";
        String line = "";
        while (line != null) {
            try {
                line = reader.readLine();
                if (line != null) {
                    if (line.startsWith("{\"hash\":")) {
                        parseContrastJavaFinding(tr, line);
                    } else if (line.contains(NODEFINDINGLINEINDICATOR)) {
                        parseContrastNodeFinding(tr, line);
                    } // Agent Version check for Java
                    else if (line.contains("Agent Version:")) {
                        String version =
                                line.substring(line.indexOf("Version:") + "Version:".length());
                        tr.setToolVersion(version.trim());
                    } // Agent Version check for Node
                    else if (line.contains(NODEAGENTVERSIONLINEINDICATOR)) {
                        String version =
                                line.substring(
                                        line.indexOf(NODEAGENTVERSIONLINEINDICATOR)
                                                + NODEAGENTVERSIONLINEINDICATOR.length(),
                                        line.indexOf(','));
                        tr.setToolVersion(version);
                    } // First line check for Java
                    else if (firstLine == null
                            && line.contains("DEBUG - >>> [URL")
                            && line.contains(FIRSTLINEINDICATOR)) {
                        firstLine =
                                line; // Once set, don't set again, hence 'firstLine == null' check
                    } // First line check for Node
                    else if (firstLine == null
                            && line.contains("Received request ")
                            && line.contains(FIRSTLINEINDICATOR)) {
                        firstLine = line;
                    } else if (line.contains("DEBUG - >>>") || line.contains("Received request ")) {
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

    private void parseContrastNodeFinding(TestSuiteResults tr, String line) throws Exception {

        // Node findings look like:
        // debug: 2021-05-12T21:00:46.118Z 12631 contrast:rules:sinks - crypto-bad-mac:
        // /julietjs/sqli-00/JulietJSTest00001
        // However, there are similar lines like this we have to avoid:
        // debug: 2021-05-12T21:00:30.487Z 12631 contrast:rules:sinks - loading provider for
        // hardcoded-password

        if (line.contains("loading provider")) return;

        int i = line.indexOf(NODEFINDINGLINEINDICATOR);
        if (i < 0) {
            System.out.println(
                    "Bug in Contrast Parser. "
                            + NODEFINDINGLINEINDICATOR
                            + " not found in line: "
                            + line);
            return;
        }

        line = line.substring(i + NODEFINDINGLINEINDICATOR.length());
        String[] elements = line.split(":");

        TestCaseResult tcr = new TestCaseResult();
        tcr.setCWE(cweLookup(elements[0]));
        tcr.setCategory(elements[0]);

        if (tcr.getCWE() != 0 && elements[1].contains(BenchmarkScore.TESTCASENAME)) {
            tcr.setNumber(testNumber(elements[1]));
            tr.put(tcr);
        }
    }

    private void parseContrastJavaFinding(TestSuiteResults tr, String json) throws Exception {

        TestCaseResult tcr = new TestCaseResult();

        try {
            JSONObject obj = new JSONObject(json);
            String ruleId = obj.getString("ruleId");
            int cweNum = cweLookup(ruleId);
            if (CweNumber.DONTCARE == cweNum)
                return; // Don't bother parsing finding types we don't care about
            tcr.setCWE(cweNum);
            tcr.setCategory(ruleId);

            JSONObject request = obj.getJSONObject("request");
            String uri = request.getString("uri");

            if (tcr.getCWE() != 0 && uri.contains(BenchmarkScore.TESTCASENAME)) {
                // Normal uri's look like: "uri":"/benchmark/cmdi-00/BenchmarkTest00215", but for
                // web services, they can look like:
                // "uri":"/benchmark/rest/xxe-00/BenchmarkTest03915/send"
                // At this point testNumber could contain '00215', or '03915/send'
                tcr.setNumber(testNumber(uri));
                // System.out.println( tcr.getNumber() + "\t" + tcr.getCWE() + "\t" +
                // tcr.getCategory() );
                tr.put(tcr);
            }
        } catch (Exception e) {
            // There are a few crypto related findings not associated with
            // a request, so ignore findings associated with those.
            if (json.contains("\"ruleId\":\"crypto-bad-ciphers\"")
                    || json.contains("\"ruleId\":\"crypto-bad-mac\"")
                    || json.contains("\"ruleId\":\"crypto-weak-randomness\"")) {
                // do nothing
            } else {
                System.err.println("Contrast Java Results Parse error for: " + json);
                e.printStackTrace();
            }
        }
    }

    static int cweLookup(String rule) {
        switch (rule) {
            case "autocomplete-missing":
                // Not sure the CWE for this.
            case "cache-controls-missing":
                // return 525; // Web Browser Cache Containing Sensitive Info
            case "clickjacking-control-missing":
                // return 1021; // Improper Restriction of Rendered UI Layers (i.e., Clickjacking)
                return CweNumber.DONTCARE;
            case "unsafe-code-execution": // Note: This is technically CWE 95 'Eval Injection'
            case "cmd-injection":
                return CweNumber.COMMAND_INJECTION;
            case "cookie-flags-missing":
                return CweNumber.INSECURE_COOKIE;
            case "crypto-bad-ciphers":
                return CweNumber.WEAK_CRYPTO_ALGO; // weak encryption
            case "crypto-bad-mac":
                return CweNumber.WEAK_HASH_ALGO; // weak hash
            case "crypto-weak-randomness":
                return CweNumber.WEAK_RANDOM;
            case "csp-header-insecure":
            case "csp-header-missing":
                return CweNumber.DONTCARE;
            case "header-injection":
                return CweNumber.HTTP_RESPONSE_SPLITTING;
            case "hql-injection":
                return CweNumber.HIBERNATE_INJECTION;
            case "hsts-header-missing":
                // return 319; // CWE-319: Cleartext Transmission of Sensitive Information
                return CweNumber.DONTCARE;
            case "insecure-jsp-access":
                return CweNumber.DONTCARE;
            case "ldap-injection":
                return CweNumber.LDAP_INJECTION;
            case "log-injection":
                return CweNumber.DONTCARE;
            case "nosql-injection":
                return CweNumber.SQL_INJECTION; // nosql injection
            case "path-traversal":
                return CweNumber.PATH_TRAVERSAL;
            case "reflected-xss":
                return CweNumber.XSS;
            case "reflection-injection":
                return CweNumber.DONTCARE;
            case "redos":
                // return 400; // regex denial of service - CWE-400: Uncontrolled Resource
                // Consumption
                return CweNumber.DONTCARE;
            case "sql-injection":
                return CweNumber.SQL_INJECTION;
            case "trust-boundary-violation":
                return CweNumber.TRUST_BOUNDARY_VIOLATION; // trust boundary
            case "unsafe-readline":
            case "xcontenttype-header-missing":
                return CweNumber.DONTCARE;
            case "xpath-injection":
                return CweNumber.XPATH_INJECTION;
            case "xxssprotection-header-disabled":
                return CweNumber.DONTCARE;
            case "xxe":
                return CweNumber.XXE; // XML eXternal entity injection
            default:
                System.out.println("WARNING: Contrast-Unrecognized finding type: " + rule);
        }

        return 0;
    }

    private String calculateTime(String firstLine, String lastLine) {
        try {
            if (firstLine == null || !firstLine.contains(" ")) {
                System.out.println(
                        "WARNING: First line to parse start time from has unexpected format: "
                                + firstLine);
                return null;
            }
            if (lastLine == null || !lastLine.contains(" ")) {
                System.out.println(
                        "WARNING: Last line to parse start time from has unexpected format: "
                                + lastLine);
                return null;
            }
            String start = firstLine.split(" ")[1];
            String stop = lastLine.split(" ")[1];
            SimpleDateFormat sdf;
            if (start.endsWith("Z")) {
                // Node log format: "2021-05-12T21:00:46.095Z"
                sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
            } else sdf = new SimpleDateFormat("HH:mm:ss,SSS"); // Java log format
            Date startTime = sdf.parse(start);
            Date stopTime = sdf.parse(stop);
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
