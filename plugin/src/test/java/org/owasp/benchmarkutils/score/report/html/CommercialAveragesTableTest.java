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
import org.owasp.benchmarkutils.score.CategoryResults;
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
                        .setToolResults(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "first category",
                                                        0.5,
                                                        0.06666666666666667,
                                                        0.05,
                                                        35))
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "second category",
                                                        0.5185185185185185,
                                                        0.9333333333333333,
                                                        0.65,
                                                        35))
                                        .build())
                        .build();

        Tool secondTool =
                ToolBuilder.builder()
                        .setIsCommercial(true)
                        .setToolResults(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "first category",
                                                        0.7321428571428571,
                                                        1.0,
                                                        0.530622009569378,
                                                        455))
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "second category",
                                                        0.9523809523809523,
                                                        0.58130081300813008,
                                                        0.204784688995215311,
                                                        455))
                                        .build())
                        .build();

        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName(""), "");

        Set<Tool> tools = asSet(firstTool, secondTool);

        commercialAveragesTable.add(new ScatterVulns("", 0, "first category", tools, null));
        commercialAveragesTable.add(new ScatterVulns("", 0, "second category", tools, null));

        assertTrue(commercialAveragesTable.hasEntries());

        String actual = commercialAveragesTable.render();

        assertTrue(
                actual.startsWith(
                        "<table class=\"table\"><tr><th>Vulnerability Category</th>"
                                + "<th>Low Tool Type</th><th>Low Score</th><th>Ave Score</th><th>High Score</th>"
                                + "<th>High Tool Type</th></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>first category</td><td>SAST</td><td>47</td><td>47</td><td>47</td><td>SAST</td></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>second category</td><td>SAST</td><td>38</td><td>38</td><td>38</td><td>SAST</td></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>Average across all categories for 1 tools</td><td></td><td>42.5</td><td>42.5</td>"
                                + "<td>42.5</td><td></td></tr>"));
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
                        .setToolResults(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "first category",
                                                        0.5,
                                                        0.66666666666666667,
                                                        0.05,
                                                        35))
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "second category",
                                                        0.5185185185185185,
                                                        0.9333333333333333,
                                                        0.35,
                                                        35))
                                        .build())
                        .build();

        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName(""), "");

        Set<Tool> tools = asSet(tool);

        commercialAveragesTable.add(new ScatterVulns("", 0, "first category", tools, null));
        commercialAveragesTable.add(new ScatterVulns("", 0, "second category", tools, null));

        assertTrue(commercialAveragesTable.hasEntries());

        String actual = commercialAveragesTable.render();

        assertTrue(
                actual.contains(
                        "<tr><td>first category</td><td>SAST</td><td class=\"success\">62</td><td>62</td>"
                                + "<td class=\"success\">62</td><td>SAST</td></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>second category</td><td>SAST</td><td class=\"success\">58</td><td>58</td>"
                                + "<td class=\"success\">58</td><td>SAST</td></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>Average across all categories for 1 tools</td><td></td><td>60.0</td><td>60.0</td>"
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
                        .setToolResults(
                                ToolResultsBuilder.builder()
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "first category",
                                                        0.5,
                                                        0.06666666666666667,
                                                        0.65,
                                                        35))
                                        .addCategoryResult(
                                                new CategoryResults(
                                                        "second category",
                                                        0.5185185185185185,
                                                        0.3333333333333333,
                                                        0.95,
                                                        35))
                                        .build())
                        .build();

        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName(""), "");

        Set<Tool> tools = asSet(tool);

        commercialAveragesTable.add(new ScatterVulns("", 0, "first category", tools, null));
        commercialAveragesTable.add(new ScatterVulns("", 0, "second category", tools, null));

        assertTrue(commercialAveragesTable.hasEntries());

        String actual = commercialAveragesTable.render();

        assertTrue(
                actual.contains(
                        "<tr><td>first category</td><td>SAST</td><td class=\"danger\">-58</td><td>-58</td>"
                                + "<td class=\"danger\">0</td><td>null</td></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>second category</td><td>SAST</td><td class=\"danger\">-62</td><td>-62</td>"
                                + "<td class=\"danger\">0</td><td>null</td></tr>"));
        assertTrue(
                actual.contains(
                        "<tr><td>Average across all categories for 1 tools</td><td></td><td>-60.0</td><td>-60.0</td>"
                                + "<td>0.0</td><td></td></tr>"));
    }

    @Test
    void buildsFilename() {
        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName("Benchmark"), "1.2");

        assertEquals(
                "Benchmark_v1.2_Scorecard_for_Commercial_Tools.html",
                commercialAveragesTable.filename());
    }
}
