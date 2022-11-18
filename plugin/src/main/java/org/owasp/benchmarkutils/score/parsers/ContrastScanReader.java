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
 * @author Sascha Knoop
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import com.contrastsecurity.sarif.SarifSchema210;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ContrastScanReader extends Reader {

    // TODO: This shouldn't use 5 hard coded \\d. BenchmarkScore.TESTIDLENGTH defines the length of
    // the numbers in a test case
    // In fact, there are lots of examples of parsing out test case numbers, so this regex probably
    // shouldn't be used at all.
    private static final Pattern ResultNamePattern =
            Pattern.compile(".*? BenchmarkTest(\\d\\d\\d\\d\\d)\\.java.*");

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.isJson()
                    && resultFile
                            .json()
                            .getJSONArray("runs")
                            .getJSONObject(0)
                            .getJSONObject("tool")
                            .getJSONObject("driver")
                            .getString("name")
                            .equals("Contrast Scan");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        Report report = jsonMapper.readValue(resultFile.content(), Report.class);

        TestSuiteResults tr =
                new TestSuiteResults("Contrast Scan", true, TestSuiteResults.ToolType.SAST);

        try {
            // Parse using SARIF format to get start/end time. And in the future, the tool name
            // when that value is actually populated.
            // Ideally, we'd do all the parsing using the SARIF format.
            SarifSchema210 sarif =
                    new ObjectMapper().readValue(resultFile.content(), SarifSchema210.class);
            // List<Result> sarifResults = sarif.getRuns().get(0).getResults();
            // getVersion() doesn't work as those values aren't populated yet.
            // e.g., you get: "vpkg:_null,_engine:_null,_policy:_null"
            // tr.setToolVersion(sarif.getRuns().get(0).getTool().getDriver().getVersion());
            Date start = sarif.getRuns().get(0).getInvocations().get(0).getStartTimeUtc();
            Date end = sarif.getRuns().get(0).getInvocations().get(0).getEndTimeUtc();
            Math.abs(end.getTime() - start.getTime());
            tr.setTime(TestSuiteResults.formatTime(Math.abs(end.getTime() - start.getTime())));
        } catch (Exception e) {
            // If parsing fails, do nothing for now.
        }

        /*        for (Result r : sarifResults) {
                    String ruleId = r.getRuleId();
                    int cwe = ContrastAssessReader.cweLookup(ruleId);
                    if (cwe == CweNumber.DONTCARE) {
                        continue;
                    }

                    CodeFlow cf = r.getCodeFlows().get(0);
                    String message = cf.getMessage().getText(); // BUG: Either CodeFlows or Messages don't always exist
                    // Above needs to be rewritten to use location.physicalLocation.artifactLocation.uri, like below

                    Integer testNum = extractTestNum(message);
                    TestCaseResult tcr = new TestCaseResult();
                    tcr.setCWE(cwe);
                    tcr.setCategory(ruleId);
                    tcr.setNumber(testNum);
                    if (tcr.getCWE() != 0) {
                        tr.put(tcr);
                    }
                }
        */

        // TODO: This should use SARIF format, but that doesn't work yet, per above comment.
        for (Report.Run run : report.runs) {
            for (Report.Run.Result result : run.results) {
                int cwe = ContrastAssessReader.cweLookup(result.rule);

                if (cwe <= 0) {
                    continue;
                }

                for (Report.Run.Result.Location location : result.locations) {
                    String testfile =
                            extractFilename(location.physicalLocation.artifactLocation.uri);

                    if (testfile.startsWith(BenchmarkScore.TESTCASENAME)) {
                        TestCaseResult tcr = new TestCaseResult();

                        tcr.setCategory(result.rule);
                        tcr.setCWE(cwe);
                        tcr.setNumber(testNumber(testfile));

                        tr.put(tcr);
                    }
                }
            }
        }

        return tr;
    }

    // TODO: There are lots of examples of how to do this without a regex
    private static Integer extractTestNum(String msg) {
        // extract benchmark name in the form:
        // Found tainted data flow from BenchmarkTest01870.java:100...
        Matcher m = ResultNamePattern.matcher(msg);
        if (!m.matches()) {
            return -1;
        }
        String name = m.group(1);

        return Integer.parseInt(name);
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {

        public List<Run> runs;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Run {

            public List<Result> results;
            // public List<Invocation> invocations;

            @JsonIgnoreProperties(ignoreUnknown = true)
            private static class Result {

                @JsonProperty("ruleId")
                public String rule;

                public List<Location> locations;

                @JsonIgnoreProperties(ignoreUnknown = true)
                private static class Location {

                    // public String rule; // Unused??

                    public PhysicalLocation physicalLocation;

                    @JsonIgnoreProperties(ignoreUnknown = true)
                    private static class PhysicalLocation {

                        public ArtifactLocation artifactLocation;

                        @JsonIgnoreProperties(ignoreUnknown = true)
                        private static class ArtifactLocation {

                            public String uri;
                        }
                    }
                }
            }

            // The following doesn't work right, for the unit tests anyway.
            /*@JsonIgnoreProperties(ignoreUnknown = true)
            private static class Invocation {

                @JsonProperty("startTimeUtc")
                public String startTime;

                @JsonProperty("endTimeUtc")
                public String endTime;
            }*/
        }
    }
}
