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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class Rapid7Reader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("VulnSummary");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Rapid7 AppSpider", true, TestSuiteResults.ToolType.DAST);

        Report report = xmlMapper.readValue(resultFile.content(), Report.class);

        tr.setTime(report.duration);
        tr.setToolVersion(report.version);

        for (Report.Vulnerability vulnerability : report.vulnerabilities) {
            try {
                String testfile = extractFilenameWithoutEnding(vulnerability.url);

                if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
                    TestCaseResult tcr = new TestCaseResult();

                    tcr.setCategory(vulnerability.vulnType);
                    tcr.setEvidence(vulnerability.attackType);
                    tcr.setCWE(cweLookup(vulnerability.cwe, vulnerability.attackType));
                    tcr.setNumber(testNumber(testfile));

                    tr.put(tcr);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return tr;
    }

    private int cweLookup(String cweNum, String evidence) {
        int cwe = 0;
        if (cweNum != null && !cweNum.isEmpty()) {
            cwe = Integer.parseInt(cweNum);
        }

        switch (cwe) {
            case 0:
                switch (evidence) {
                        // These are the ones we've seen. Print out any new ones to make sure its
                        // mapped properly.
                    case "Reflection":
                        return CweNumber.XSS; // Causes their XSS score to go from 0% to: TP:34.55%
                        // FP:11.48%

                    case "Customer Authentication Credential (Username)":
                    case "Email address":
                    case "Javascript \"strict mode\" is not defined.":
                    case "Left arrow":
                    case "Mobile Browser":
                    case "Stored Discover number":
                    case "Stored MasterCard number":
                    case "Stored Visa number":
                    case "Strict-Transport-Security header not found in the response from HTTPS site":
                    case "The Content Security Policy hasn't been declared either through the meta-tag or the header.":
                    case "Undefined charset attribute":
                    case "X-Content-Type-Options header not found":
                    case "X-Frame-Options HTTP header checking":
                    case "X-XSS-Protection header not found":
                        return 0;
                    default:
                        {
                            // If this prints out anything new, add to this mapping so we know it's
                            // mapped properly.
                            System.out.println(
                                    "Found new unmapped finding with evidence: " + evidence);
                            return 0; // In case they add any new mappings
                        }
                }
            case 79:
                switch (evidence) {
                    case "HttpOnly attribute not set":
                        return CweNumber.COOKIE_WITHOUT_HTTPONLY;
                    default:
                        return CweNumber.XSS; // Leave the rest as is
                }
            case 80:
                switch (evidence) {
                        // These map Basic XSS to XSS - Causing their XSS TP rate to go up almost
                        // 12%
                    case "Filter evasion - script alert injection, no round brackets":
                    case "Filter evasion - script prompt injection, no round brackets":
                    case "Unfiltered <script> tag after single quotation mark":
                    case "Unfiltered <script> tag after double quotation mark":
                    case "Unfiltered <script> tag":
                    case "body with onload (original)":
                    case "img tag with onerror":
                    case "script include":
                    case "script tag":
                        return CweNumber.XSS;
                    case "SameSite attribute is not set to \"strict\" or \"lax\"":
                        return CweNumber.CSRF;
                    default:
                        {
                            // If this prints out anything new, add to this mapping so we know it's
                            // mapped properly.
                            System.out.println(
                                    "Found new CWE 80 (mapping to 79) with evidence: " + evidence);
                            return CweNumber.XSS; // In case they add any new mappings
                        }
                }
            case 201: // SQL instruction files - This causes their TP rate to go up 4% but FP rate
                // up 6.5%
            case 209: // Find SQL query constructions - This causes their TP rate to go up 2.5% but
                // FP rate up 7.75%
                return CweNumber.SQL_INJECTION;
        }
        return cwe;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {

        @JacksonXmlProperty(localName = "AppVersion")
        public String version;

        @JacksonXmlProperty(localName = "ScanDuration")
        public String duration;

        @JacksonXmlElementWrapper(localName = "VulnList")
        @JacksonXmlProperty(localName = "Vuln")
        public List<Vulnerability> vulnerabilities;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Vulnerability {

            @JacksonXmlProperty(localName = "VulnType")
            public String vulnType;

            @JacksonXmlProperty(localName = "AttackType")
            public String attackType;

            @JacksonXmlProperty(localName = "CweId")
            public String cwe;

            @JacksonXmlProperty(localName = "Url")
            public String url;
        }
    }
}
