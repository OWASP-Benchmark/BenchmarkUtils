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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ContrastJsonReader extends Reader {

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

        for (Report.Run run : report.runs) {
            for (Report.Run.Result result : run.results) {
                int cwe = figureCwe(result.rule);

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

    private int figureCwe(String rule) {
        switch (rule) {
            case "autocomplete-missing":
                return -1; // what's the actual issue here?
            case "cmd-injection":
                return CweNumber.COMMAND_INJECTION;
            case "cookie-flags-missing":
                return CweNumber.INSECURE_COOKIE;
            case "crypto-bad-ciphers":
                return CweNumber.BROKEN_CRYPTO;
            case "crypto-bad-mac":
                return CweNumber.REVERSIBLE_HASH;
            case "crypto-weak-randomness":
                return CweNumber.WEAK_RANDOM;
            case "ldap-injection":
                return CweNumber.LDAP_INJECTION;
            case "path-traversal":
                return CweNumber.PATH_TRAVERSAL;
            case "sql-injection":
                return CweNumber.SQL_INJECTION;
            case "trust-boundary-violation":
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case "xpath-injection":
                return CweNumber.XPATH_INJECTION;
            case "reflected-xss":
                return CweNumber.XSS;
        }

        return -1;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {

        public List<Run> runs;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Run {

            public List<Result> results;

            @JsonIgnoreProperties(ignoreUnknown = true)
            private static class Result {

                @JsonProperty("ruleId")
                public String rule;

                public List<Location> locations;

                @JsonIgnoreProperties(ignoreUnknown = true)
                private static class Location {

                    public String rule;

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
        }
    }
}
