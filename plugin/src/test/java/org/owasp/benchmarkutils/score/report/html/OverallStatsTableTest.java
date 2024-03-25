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
 * @created 2024
 */
package org.owasp.benchmarkutils.score.report.html;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.TestSuiteResults.ToolType;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.ToolResults;
import org.owasp.benchmarkutils.score.builder.ConfigurationBuilder;
import org.owasp.benchmarkutils.score.builder.ToolBuilder;

class OverallStatsTableTest {

    @BeforeEach
    void setUp() {
        BenchmarkScore.config = Configuration.fromDefaultConfig();
    }

    @Test
    void createsResultTableForTools() {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setMixedMode(false)
                        .setIncludePrecision(false)
                        .build();

        Tool firstTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(testSuiteResults("Tool A", "1.0", true, ToolType.SAST))
                        .setToolResults(toolResults(0.7, 0.5))
                        .setIsCommercial(true)
                        .build();
        Tool secondTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(
                                testSuiteResults("Tool B", "2.0", false, ToolType.DAST))
                        .setToolResults(toolResults(0.8, 0.6))
                        .build();

        OverallStatsTable table = new OverallStatsTable(config, "Benchmark");

        String actual = table.generateFor(asSet(firstTool, secondTool));

        assertTrue(
                actual.startsWith(
                        "<table class=\"table\"><tr><th>Tool</th><th>Type</th>"
                                + "<th>${tprlabel}*</th><th>FPR*</th><th>Score*</th></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>Tool A v1.0</td><td>SAST</td><td>70.00%</td>"
                                + "<td>50.00%</td><td>20.00%</td></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>Tool B v2.0</td><td>DAST</td><td>80.00%</td>"
                                + "<td>60.00%</td><td>20.00%</td></tr>"));
        assertTrue(
                actual.endsWith(
                        "</table><p>*-Please refer to each tool's scorecard for "
                                + "the data used to calculate these values.</p>"));
    }

    private TestSuiteResults testSuiteResults(
            String name, String version, boolean isCommercial, ToolType type) {
        TestSuiteResults results = new TestSuiteResults(name, isCommercial, type);

        results.setToolVersion(version);

        return results;
    }

    private ToolResults toolResults(double tpRate, double fpRate) {
        ToolResults results = new ToolResults();

        results.setTruePositiveRate(tpRate);
        results.setFalsePositiveRate(fpRate);

        return results;
    }

    private Set<Tool> asSet(Tool... tools) {
        return Arrays.stream(tools).collect(Collectors.toSet());
    }

    @Test
    void showsSuccessColumns() {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setMixedMode(false)
                        .setIncludePrecision(false)
                        .build();

        Tool firstTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(
                                testSuiteResults("Tool A", "1.0", false, ToolType.SAST))
                        .setToolResults(toolResults(0.8, 0.1))
                        .build();

        OverallStatsTable table = new OverallStatsTable(config, "Benchmark");

        String actual = table.generateFor(asSet(firstTool));

        assertTrue(
                actual.contains(
                        "<tr class=\"success\"><td>Tool A v1.0</td><td>SAST</td>"
                                + "<td>80.00%</td><td>10.00%</td><td>70.00%</td></tr>"));
    }

    @Test
    void showsDangerColumns() {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setMixedMode(false)
                        .setIncludePrecision(false)
                        .build();

        Tool firstTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(
                                testSuiteResults("Tool A", "1.0", false, ToolType.SAST))
                        .setToolResults(toolResults(0.2, 0.2))
                        .build();

        OverallStatsTable table = new OverallStatsTable(config, "Benchmark");

        String actual = table.generateFor(asSet(firstTool));

        assertTrue(
                actual.contains(
                        "<tr class=\"danger\"><td>Tool A v1.0</td><td>SAST</td>"
                                + "<td>20.00%</td><td>20.00%</td><td>0.00%</td></tr>"));
    }

    @Test
    void hidesCommercialToolsInAverageMode() {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(true)
                        .setMixedMode(false)
                        .setIncludePrecision(false)
                        .build();

        Tool firstTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(testSuiteResults("Tool A", "", true, ToolType.SAST))
                        .setIsCommercial(true)
                        .build();
        Tool secondTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(testSuiteResults("Tool B", "", false, ToolType.SAST))
                        .setToolResults(toolResults(0, 0))
                        .build();

        OverallStatsTable table = new OverallStatsTable(config, "Benchmark");

        String actual = table.generateFor(asSet(firstTool, secondTool));

        assertFalse(actual.contains("Tool A"));
        assertTrue(actual.contains("Tool B"));
    }

    @Test
    void createsResultTableInMixedMode() {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setMixedMode(true)
                        .setIncludePrecision(false)
                        .build();

        TestSuiteResults firstToolResults = testSuiteResults("Tool A", "1.0", true, ToolType.SAST);
        firstToolResults.setTestSuiteVersion("1.2");
        Tool firstTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(firstToolResults)
                        .setToolResults(toolResults(0.7, 0.5))
                        .setIsCommercial(true)
                        .build();
        TestSuiteResults secondToolResults =
                testSuiteResults("Tool B", "2.0", false, ToolType.DAST);
        secondToolResults.setTestSuiteVersion("1.3");
        Tool secondTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(secondToolResults)
                        .setToolResults(toolResults(0.8, 0.6))
                        .build();

        OverallStatsTable table = new OverallStatsTable(config, "Benchmark");

        String actual = table.generateFor(asSet(firstTool, secondTool));

        assertTrue(actual.contains("<th>Benchmark Version</th>"));
        assertTrue(actual.contains("<td>Tool A v1.0</td><td>1.2</td>"));
        assertTrue(actual.contains("<td>Tool B v2.0</td><td>1.3</td>"));
    }

    @Test
    void createsResultTableWithPrecision() {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setMixedMode(false)
                        .setIncludePrecision(true)
                        .build();

        ToolResults firstToolResults = toolResults(0.7, 0.5);
        firstToolResults.setPrecision(0.12345);
        Tool firstTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(testSuiteResults("Tool A", "1.0", true, ToolType.SAST))
                        .setToolResults(firstToolResults)
                        .setIsCommercial(true)
                        .build();
        ToolResults secondToolResults = toolResults(0.8, 0.6);
        secondToolResults.setPrecision(0.33333);
        Tool secondTool =
                ToolBuilder.builder()
                        .setTestSuiteResults(
                                testSuiteResults("Tool B", "2.0", false, ToolType.DAST))
                        .setToolResults(secondToolResults)
                        .build();

        OverallStatsTable table = new OverallStatsTable(config, "Benchmark");

        String actual = table.generateFor(asSet(firstTool, secondTool));

        assertTrue(actual.contains("<th>Precision*</th><th>F-score*</th>"));
        assertTrue(
                actual.contains("<td>Tool A v1.0</td><td>SAST</td><td>12.35%</td><td>0.2099</td>"));
        assertTrue(
                actual.contains("<td>Tool B v2.0</td><td>DAST</td><td>33.33%</td><td>0.4706</td>"));
    }
}
