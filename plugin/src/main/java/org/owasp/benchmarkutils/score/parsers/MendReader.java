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
 * @author Sascha Knoop
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlElementWrapper;
import com.fasterxml.jackson.dataformat.xml.annotation.JacksonXmlProperty;
import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class MendReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml")
                && resultFile.xmlRootNodeName().equals("ReportModel");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Mend", true, TestSuiteResults.ToolType.SAST);

        Report report = xmlMapper.readValue(resultFile.content(), Report.class);

        tr.setTime(report.stats.duration);

        for (Report.EngineResults engineResults : report.engineResults) {
            for (Report.EngineResults.Result result : engineResults.results) {
                for (Report.EngineResults.Result.Vulnerability vulnerability :
                        result.vulnerabilities) {
                    try {
                        String testfile = extractFilenameWithoutEnding(vulnerability.filename);

                        if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
                            TestCaseResult tcr = new TestCaseResult();

                            tcr.setCategory(result.type.name);
                            tcr.setCWE(result.type.cwe.asNumber());
                            tcr.setNumber(testNumber(testfile));

                            tr.put(tcr);
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
        return tr;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {

        @JacksonXmlProperty(localName = "Stats")
        Stats stats;

        @JacksonXmlProperty(localName = "Results")
        @JacksonXmlElementWrapper(useWrapping = false)
        List<EngineResults> engineResults;

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
            List<Result> results;

            @JsonIgnoreProperties(ignoreUnknown = true)
            private static class Result {

                @JacksonXmlProperty(localName = "Type")
                Type type;

                @JacksonXmlElementWrapper(localName = "Vulnerabilities")
                @JacksonXmlProperty(localName = "Vulnerability")
                List<Vulnerability> vulnerabilities;

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
            }
        }
    }
}
