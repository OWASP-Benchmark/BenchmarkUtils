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
 * @created 2025
 */
package org.owasp.benchmarkutils.score.parsers;

import static java.lang.Integer.parseInt;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class BlackDuckReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.json().has("driver")
                && resultFile.json().get("driver").equals("polaris_blackduck");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("BlackDuck", true, TestSuiteResults.ToolType.SAST);

        Report report = jsonMapper.readValue(resultFile.content(), Report.class);

        report.items.stream()
                .filter(Item::isRelevant)
                .forEach(
                        item -> {
                            Map<String, String> properties = item.mappedProperties();

                            String testfile =
                                    extractFilenameWithoutEnding(properties.get("filename"));

                            TestCaseResult tcr = new TestCaseResult();

                            tcr.setCWE(parseInt(properties.get("cwe").substring(4)));
                            tcr.setNumber(testNumber(testfile));

                            tr.put(tcr);
                        });

        return tr;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    private static class Report {

        @JsonProperty("_items")
        public List<Item> items;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Item {

        @JsonProperty("occurrenceProperties")
        public List<Property> properties;

        public Map<String, String> mappedProperties() {
            return properties.stream().collect(Collectors.toMap(Property::key, Property::value));
        }

        public boolean isRelevant() {
            return properties.stream()
                    .anyMatch(property -> property.value.contains(BenchmarkScore.TESTCASENAME));
        }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Property {
        public String key;
        public String value;

        public String key() {
            return key;
        }

        public String value() {
            return value;
        }
    }
}
