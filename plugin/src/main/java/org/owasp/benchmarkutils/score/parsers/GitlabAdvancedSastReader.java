package org.owasp.benchmarkutils.score.parsers;

import static java.lang.Integer.parseInt;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class GitlabAdvancedSastReader extends Reader {

    // 2015-08-17T14:21:14+03:00
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return resultFile.isJson()
                    && resultFile
                            .json()
                            .getJSONObject("scan")
                            .getJSONObject("analyzer")
                            .getString("name")
                            .equals("GitLab Advanced SAST");
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("GitLab Advanced SAST", true, TestSuiteResults.ToolType.SAST);

        Report report = jsonMapper.readValue(resultFile.content(), Report.class);

        tr.setToolVersion(report.version);
        tr.setTime(formatTimeDelta(report.scanInfo.startTime, report.scanInfo.endTime));

        report.vulnerabilities.stream()
                .map(this::parseJsonResult)
                .filter(Objects::nonNull)
                .forEach(tr::put);

        return tr;
    }

    private TestCaseResult parseJsonResult(Report.Vulnerability issue) {
        Optional<Report.Vulnerability.Identifier> cweIdentifier =
                issue.identifiers.stream()
                        .filter(identifier -> "cwe".equals(identifier.type))
                        .findFirst();

        if (cweIdentifier.isEmpty()) {
            return null;
        }

        TestCaseResult tcr = new TestCaseResult();

        tcr.setCWE(parseInt(cweIdentifier.get().value));
        tcr.setNumber(testNumber(issue.location.file));

        return tcr;
    }

    private String formatTimeDelta(String start, String end) {
        try {
            return TestSuiteResults.formatTime(
                    sdf.parse(end).getTime() - sdf.parse(start).getTime());
        } catch (Exception e) {
            return "Unknown";
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {
        @JsonProperty String version;

        @JsonProperty("scan")
        ScanInfo scanInfo;

        @JsonProperty("vulnerabilities")
        List<Vulnerability> vulnerabilities;

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class ScanInfo {
            @JsonProperty("start_time")
            String startTime;

            @JsonProperty("end_time")
            String endTime;
        }

        @JsonIgnoreProperties(ignoreUnknown = true)
        private static class Vulnerability {
            @JsonProperty Location location;

            @JsonProperty List<Identifier> identifiers;

            @JsonIgnoreProperties(ignoreUnknown = true)
            private static class Location {
                @JsonProperty String file;
            }

            @JsonIgnoreProperties(ignoreUnknown = true)
            private static class Identifier {
                @JsonProperty String type;

                @JsonProperty String value;
            }
        }
    }
}
