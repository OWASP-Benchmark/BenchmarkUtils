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
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Sascha Knoop, Jan Kühl
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class MendReader extends Reader {

    /* legacy version */
    private static final String ROOT_NODE_REPORT_MODEL = "ReportModel";
    /* since 2023 */
    private static final String ROOT_NODE_REPORTS_WITH_PROJECT = "reportsWithProject";
    private static final Set<String> SUPPORTED_ROOT_NODES =
            Set.of(ROOT_NODE_REPORT_MODEL, ROOT_NODE_REPORTS_WITH_PROJECT);

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && SUPPORTED_ROOT_NODES.contains(resultFile.xmlRootNodeName());
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Mend SAST", true, TestSuiteResults.ToolType.SAST);

        Report report = xmlMapper.readValue(resultFile.content(), Report.class);

        tr.setTime(report.stats.duration);

        String rootNodeName = resultFile.xmlRootNodeName();

        for (Report.EngineResults engineResults : report.engineResults) {
            for (Report.EngineResults.Result result : engineResults.results) {
                switch (rootNodeName) {
                    case ROOT_NODE_REPORT_MODEL:
                        parseVulnerabilities(result, tr);
                        break;
                    case ROOT_NODE_REPORTS_WITH_PROJECT:
                        // Findings replaced Vulnerabilities as Mend's finding element, since 2023
                        parseFindings(result, tr);
                        break;
                    default:
                        continue;
                }
            }
        }
        return tr;
    }

    private void parseVulnerabilities(Report.EngineResults.Result result, TestSuiteResults tr) {
        for (Report.EngineResults.Result.Vulnerability vulnerability : result.vulnerabilities) {
            try {
                String testFile = extractFilenameWithoutEnding(vulnerability.filename);
                createAndAddTestCase(result, result.type.cwe.asNumber(), testFile, tr);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void parseFindings(Report.EngineResults.Result result, TestSuiteResults tr) {
        int cwe = mapCwe(result.type.cwe.asNumber());

        for (Report.EngineResults.Result.Finding finding : result.findings) {
            try {
                String testFile = extractFilenameWithoutEnding(finding.sharedStep.file);
                createAndAddTestCase(result, cwe, testFile, tr);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private void createAndAddTestCase(
            Report.EngineResults.Result result, int cwe, String testFile, TestSuiteResults tr) {
        if (!testFile.startsWith(BenchmarkScore.TESTCASENAME)) {
            return;
        }

        TestCaseResult tcr = new TestCaseResult();

        tcr.setCategory(result.type.name);
        tcr.setCWE(cwe);
        tcr.setNumber(testNumber(testFile));

        tr.put(tcr);
    }

    // CWE remap required for the Findings-based report format, since 2023
    private static int mapCwe(int cwe) {
        switch (cwe) {
            case 338:
                return CweNumber.WEAK_RANDOM;
            case 1004:
                return CweNumber.INSECURE_COOKIE;
            default:
                return cwe;
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {

        @JacksonXmlProperty(localName = "Stats")
        Stats stats;

        @JacksonXmlProperty(localName = "Results")
        @JacksonXmlElementWrapper(useWrapping = false)
        List<EngineResults> engineResults = new ArrayList<>();

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Stats {

            @JacksonXmlProperty(localName = "Duration")
            String duration;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class EngineResults {

            @JacksonXmlProperty(localName = "Language")
            String language;

            @JacksonXmlProperty(localName = "Results")
            @JacksonXmlElementWrapper(useWrapping = false)
            List<Result> results = new ArrayList<>();

            @JsonIgnoreProperties(ignoreUnknown = true)
            private static class Result {

                @JacksonXmlProperty(localName = "Type")
                Type type;

                @JacksonXmlElementWrapper(localName = "Vulnerabilities")
                @JacksonXmlProperty(localName = "Vulnerability")
                List<Vulnerability> vulnerabilities = new ArrayList<>();

                // Findings replaced Vulnerabilities as Mend's finding element, since 2023
                @JacksonXmlProperty(localName = "Findings")
                @JacksonXmlElementWrapper(useWrapping = false)
                List<Finding> findings = new ArrayList<>();

                @JsonIgnoreProperties(ignoreUnknown = true)
                private static class Type {

                    @JacksonXmlProperty(localName = "Name", isAttribute = true)
                    String name;

                    @JacksonXmlProperty(localName = "CWE")
                    Cwe cwe;

                    @JsonIgnoreProperties(ignoreUnknown = true)
                    private static class Cwe {

                        @JacksonXmlProperty(localName = "ID")
                        String id;

                        public int asNumber() {
                            return Integer.parseInt(id.substring(4));
                        }
                    }
                }

                @JsonIgnoreProperties(ignoreUnknown = true)
                private static class Vulnerability {

                    @JacksonXmlProperty(localName = "SinkFile")
                    String filename;
                }

                // New finding element, since 2023 (replaces Vulnerability)
                @JsonIgnoreProperties(ignoreUnknown = true)
                private static class Finding {

                    @JacksonXmlProperty(localName = "SharedStep")
                    SharedStep sharedStep;

                    @JsonIgnoreProperties(ignoreUnknown = true)
                    private static class SharedStep {

                        @JacksonXmlProperty(localName = "File")
                        String file;
                    }
                }
            }
        }
    }
}
