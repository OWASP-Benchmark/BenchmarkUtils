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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CategoryMetrics;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.builder.ConfigurationBuilder;
import org.owasp.benchmarkutils.score.builder.ToolBuilder;
import org.owasp.benchmarkutils.score.builder.ToolResultsBuilder;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;
import org.owasp.benchmarkutils.score.report.ScatterVulns;

class CommercialAveragesTableTest {

    @Test
    void createsAveragesTable() {
        BenchmarkScore.config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setAnonymousMode(false)
                        .build();

        Tool firstTool =
                ToolBuilder.builder()
                        .setIsCommercial(false)
                        .setToolMetrics(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Availability",
                                                        50.0,
                                                        6.666666666666667,
                                                        5.0,
                                                        35))
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Command Injection",
                                                        51.85185185185185,
                                                        93.33333333333333,
                                                        65.0,
                                                        35))
                                        .build())
                        .build();

        Tool secondTool =
                ToolBuilder.builder()
                        .setIsCommercial(true)
                        .setToolMetrics(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Availability",
                                                        73.21428571428571,
                                                        100.0,
                                                        53.0622009569378,
                                                        455))
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Command Injection",
                                                        95.23809523809523,
                                                        58.130081300813008,
                                                        20.4784688995215311,
                                                        455))
                                        .build())
                        .build();

        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName(""), "");

        Set<Tool> tools = asSet(firstTool, secondTool);

        commercialAveragesTable.add(new ScatterVulns("", 0, "Availability", tools, null));
        commercialAveragesTable.add(new ScatterVulns("", 0, "Command Injection", tools, null));

        assertTrue(commercialAveragesTable.hasEntries());

        String actual = commercialAveragesTable.render();

        final String test1 =
                "CWE</th><th>Vulnerability Category</th>"
                        + "<th>Low Tool Type</th><th>Low Score</th><th>Ave Score</th><th>High Score</th>"
                        + "<th>High Tool Type</th></tr>";
        assertTrue(
                actual.contains(test1),
                "FAILURE: Expected to contain: '" + test1 + "' but actual is: '" + actual + "'");

        final String test2 =
                "<td>Availability</td><td>SAST</td><td>47</td><td>47</td><td>47</td><td>SAST</td></tr>";
        assertTrue(
                actual.contains(test2),
                "FAILURE: Expected to contain: '" + test2 + "' but actual is: '" + actual + "'");

        final String test3 =
                "<td>Command Injection</td><td>SAST</td><td>38</td><td>38</td><td>38</td><td>SAST</td></tr>";
        assertTrue(
                actual.contains(test3),
                "FAILURE: Expected to contain: '" + test3 + "' but actual is: '" + actual + "'");

        final String test4 =
                "<td>Average across all categories for 1 tools</td><td></td><td>42.5</td><td>42.5</td>"
                        + "<td>42.5</td><td></td></tr>";
        assertTrue(
                actual.contains(test4),
                "FAILURE: Expected to contain: '" + test4 + "' but actual is: '" + actual + "'");

        assertTrue(actual.endsWith("</table>"));
    }

    private Set<Tool> asSet(Tool... tools) {
        return Arrays.stream(tools).collect(Collectors.toSet());
    }

    @Test
    void doesNotHaveEntriesByDefault() {
        assertFalse(new CommercialAveragesTable(new TestSuiteName(""), "").hasEntries());
    }

    @Test
    void showsSuccessColumns() {
        BenchmarkScore.config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setAnonymousMode(false)
                        .build();

        Tool tool =
                ToolBuilder.builder()
                        .setIsCommercial(true)
                        .setToolMetrics(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Availability",
                                                        50.0,
                                                        66.666666666666667,
                                                        5.0,
                                                        35))
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Command Injection",
                                                        51.85185185185185,
                                                        93.33333333333333,
                                                        35.0,
                                                        35))
                                        .build())
                        .build();

        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName(""), "");

        Set<Tool> tools = asSet(tool);

        commercialAveragesTable.add(new ScatterVulns("", 0, "Availability", tools, null));
        commercialAveragesTable.add(new ScatterVulns("", 0, "Command Injection", tools, null));

        assertTrue(commercialAveragesTable.hasEntries());

        String actual = commercialAveragesTable.render();

        assertTrue(
                actual.contains(
                        "<td>Availability</td><td>SAST</td><td class=\"success\">62</td><td>62</td>"
                                + "<td class=\"success\">62</td><td>SAST</td></tr>"));
        assertTrue(
                actual.contains(
                        "<td>Command Injection</td><td>SAST</td><td class=\"success\">58</td><td>58</td>"
                                + "<td class=\"success\">58</td><td>SAST</td></tr>"));
        assertTrue(
                actual.contains(
                        "<td>Average across all categories for 1 tools</td><td></td><td>60.0</td><td>60.0</td>"
                                + "<td>60.0</td><td></td></tr>"));
    }

    @Test
    void showsDangerColumns() {
        BenchmarkScore.config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setAnonymousMode(false)
                        .build();

        Tool tool =
                ToolBuilder.builder()
                        .setIsCommercial(true)
                        .setToolMetrics(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Availability",
                                                        5.0,
                                                        6.66666666666667,
                                                        65.0,
                                                        35))
                                        .addCategoryResult(
                                                new CategoryMetrics(
                                                        "Command Injection",
                                                        51.85185185185185,
                                                        33.33333333333333,
                                                        95.0,
                                                        35))
                                        .build())
                        .build();

        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName(""), "");

        Set<Tool> tools = asSet(tool);

        commercialAveragesTable.add(new ScatterVulns("", 0, "Availability", tools, null));
        commercialAveragesTable.add(new ScatterVulns("", 0, "Command Injection", tools, null));

        assertTrue(commercialAveragesTable.hasEntries());

        String actual = commercialAveragesTable.render();

        assertTrue(
                actual.contains(
                        "<td>Availability</td><td>SAST</td><td class=\"danger\">-58</td><td>-58</td>"
                                + "<td class=\"danger\">0</td>"));
        assertTrue(
                actual.contains(
                        "<td>Command Injection</td><td>SAST</td><td class=\"danger\">-62</td><td>-62</td>"
                                + "<td class=\"danger\">0</td>"));
        assertTrue(
                actual.contains(
                        "<td>Average across all categories for 1 tools</td><td></td><td>-60.0</td><td>-60.0</td>"
                                + "<td>0.0</td><td></td></tr>"));
    }

    @Test
    void buildsFilename() {
        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName("Benchmark"), "1.2");

        assertEquals(
                "Benchmark_v1.2_Scorecard_for_Commercial_Tools.html",
                commercialAveragesTable.filename(false));
    }
}
