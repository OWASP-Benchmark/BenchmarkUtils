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
 * @author Bosko Stankovic
 * @created 2017
 */
package org.owasp.benchmarkutils.score.parsers;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import java.util.ArrayList;
import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ThunderScanReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("Report")
                && resultFile.xmlRootNode().getElementsByTagName("ProjectName").getLength() == 1;
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        Report report = xmlMapper.readValue(resultFile.content(), Report.class);

        TestSuiteResults testResults =
                new TestSuiteResults("ThunderScan", true, TestSuiteResults.ToolType.SAST);

        report.vulnerabilityTypes.stream()
                .flatMap(
                        vulnerabilityType ->
                                vulnerabilityType.vulnerabilities.stream()
                                        .filter(v -> createsTestCaseResult(vulnerabilityType, v))
                                        .map(v -> toTestCaseResult(vulnerabilityType, v)))
                .forEach(testResults::put);

        return testResults;
    }

    private TestCaseResult toTestCaseResult(
            Report.VulnerabilityType vulnerabilityType,
            Report.VulnerabilityType.Vulnerability vulnerability) {
        TestCaseResult tcResult = new TestCaseResult();

        tcResult.setCWE(
                figureCwe(vulnerabilityType.name, vulnerability.function, vulnerability.filename));
        int testcasenum = testNumber(vulnerability.filename);
        if (testcasenum > 0) {
            tcResult.setNumber(testcasenum);
            tcResult.setCategory(vulnerabilityType.name);
            tcResult.setConfidence(1);
            tcResult.setEvidence(lineNumber(vulnerability));
            return tcResult;
        }
        return null; // Finding not in a test case
    }

    private boolean createsTestCaseResult(
            Report.VulnerabilityType vulnerabilityType, Report.VulnerabilityType.Vulnerability v) {
        return isBenchmarkTest(v.filename)
                && isRealVulnerability(v.function)
                && resultsInCwe(vulnerabilityType, v);
    }

    private String lineNumber(Report.VulnerabilityType.Vulnerability vulnerability) {
        return vulnerability.functionCalls.get(0).callStackItem.line;
    }

    private boolean resultsInCwe(
            Report.VulnerabilityType vulnerabilityType, Report.VulnerabilityType.Vulnerability v) {
        return figureCwe(vulnerabilityType.name, v.function, v.filename) != -1;
    }

    private boolean isBenchmarkTest(String filename) {
        return filename.contains(BenchmarkScore.TESTCASENAME);
    }

    private boolean isRealVulnerability(String function) {
        return !function.matches("/printStackTrace|Cookie$|getMessage$/");
    }

    private int figureCwe(String type, String function, String filename) {
        switch (type) {
            case "SQL Injection":
                return CweNumber.SQL_INJECTION;
            case "File Disclosure":
            case "File Manipulation":
                return CweNumber.PATH_TRAVERSAL;
            case "Command Execution":
                return CweNumber.COMMAND_INJECTION;
            case "Cross Site Scripting":
                return CweNumber.XSS;
            case "LDAP Injection":
                return CweNumber.LDAP_INJECTION;
            case "XPATH Injection":
                return CweNumber.XPATH_INJECTION;
            case "Misc. Dangerous Functions":
                if (function.contains("Weak Enc")) {
                    return CweNumber.WEAK_CRYPTO_ALGO;
                }

                if (function.contains("Weak Hash")) {
                    return CweNumber.WEAK_HASH_ALGO;
                }

                if (function.contains("Weak Random")) {
                    return CweNumber.WEAK_RANDOM;
                }

                if (function.contains("putValue") || function.contains("setAttribute")) {
                    return CweNumber.TRUST_BOUNDARY_VIOLATION;
                }

                if (function.contains("setSecure")) {
                    return CweNumber.INSECURE_COOKIE;
                }

                return -1;
            case "JSP Page Execution":
            case "Dangerous File Extensions":
            case "Arbitrary Server Connection":
            case "Log Forging":
            case "Mail Relay":
            case "HTTP Response Splitting":
                return -1;
            default:
                System.out.println(
                        "INFO: Unable to figure out cwe for: "
                                + type
                                + ", "
                                + function
                                + " @ "
                                + filename);
                return -1;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {

        @JacksonXmlProperty(localName = "VulnerabilityType")
        @JacksonXmlElementWrapper(useWrapping = false)
        public List<VulnerabilityType> vulnerabilityTypes;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class VulnerabilityType {

            @JacksonXmlProperty(localName = "Name", isAttribute = true)
            public String name;

            @JacksonXmlElementWrapper(useWrapping = false)
            @JacksonXmlProperty(localName = "Vulnerability")
            public List<Vulnerability> vulnerabilities = new ArrayList<>();

            @JsonIgnoreProperties(ignoreUnknown = true)
            private static class Vulnerability {

                @JacksonXmlProperty(localName = "File")
                public String filename;

                @JacksonXmlProperty(localName = "Function")
                public String function;

                @JacksonXmlElementWrapper(useWrapping = false)
                @JacksonXmlProperty(localName = "FunctionCalls")
                public List<FunctionCalls> functionCalls;

                @JsonIgnoreProperties(ignoreUnknown = true)
                private static class FunctionCalls {

                    @JacksonXmlProperty(localName = "CallStackItem")
                    public CallStackItem callStackItem;

                    @JsonIgnoreProperties(ignoreUnknown = true)
                    private static class CallStackItem {

                        @JacksonXmlProperty(localName = "Line", isAttribute = true)
                        public String line;
                    }
                }
            }
        }
    }
}
