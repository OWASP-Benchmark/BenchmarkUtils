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

import static java.util.Collections.emptyMap;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.TestSuiteResults.ToolType;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.builder.ConfigurationBuilder;
import org.owasp.benchmarkutils.score.builder.TestSuiteResultsBuilder;
import org.owasp.benchmarkutils.score.builder.ToolBuilder;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;

class ToolScorecardTest {

    private File tmpDir;

    @BeforeEach
    void setUp() throws IOException {
        tmpDir = Files.createTempDirectory("Benchmark.ToolScorecardTest").toFile();
    }

    @Test
    void createsScorecard() throws IOException {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setAnonymousMode(false)
                        .build();

        BenchmarkScore.config = config;

        ToolScorecard toolScorecard =
                new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("Benchmark"));

        AtomicBoolean toolBarChartCalled = new AtomicBoolean(false);

        Tool someTool =
                ToolBuilder.builder()
                        .setIsCommercial(false)
                        .setTestSuiteResults(
                                TestSuiteResultsBuilder.builder()
                                        .setToolname("Some Tool")
                                        .setToolVersion("1.0")
                                        .setToolType(ToolType.SAST)
                                        .build())
                        .build();

        toolScorecard.setToolBarChart(
                tool -> {
                    assertEquals(someTool.getToolNameAndVersion(), tool.getToolNameAndVersion());

                    toolBarChartCalled.set(true);
                });

        toolScorecard.setToolReport(
                (currentTool, title, scorecardImageFile) ->
                        currentTool.getToolNameAndVersion()
                                + "\n"
                                + title
                                + "\n"
                                + scorecardImageFile.getAbsolutePath());

        toolScorecard.generate(someTool);

        File[] files = requireNonNull(tmpDir.listFiles());
        assertEquals(2, files.length);

        assertTrue(fileWithEnding(files, "png").isPresent());

        Optional<File> htmlFile = fileWithEnding(files, "html");

        assertTrue(htmlFile.isPresent());
        List<String> htmlLines = Files.readAllLines(htmlFile.get().toPath());

        assertEquals(3, htmlLines.size());
        assertEquals("Some Tool v1.0", htmlLines.get(0));
        assertEquals("OWASP Benchmark Scorecard for Some Tool v1.0 (SAST)", htmlLines.get(1));
        assertEquals(
                tmpDir.getAbsolutePath()
                        + File.separator
                        + "Benchmark_v1.2_Scorecard_for_Some_Tool_v1.0.png",
                htmlLines.get(2));

        assertTrue(toolBarChartCalled.get());
    }

    private static Optional<File> fileWithEnding(File[] files, String ending) {
        return Arrays.stream(files).filter(f -> f.getName().endsWith(ending)).findAny();
    }

    @Test
    void doesNotCreateScorecardForCommercialToolsInAveOnlyMode() {
        Configuration config = ConfigurationBuilder.builder().setShowAveOnlyMode(true).build();

        BenchmarkScore.config = config;

        ToolScorecard toolScorecard =
                new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("Benchmark"));

        AtomicBoolean toolBarChartCalled = new AtomicBoolean(false);

        Tool someTool = ToolBuilder.builder().setIsCommercial(true).build();

        toolScorecard.setToolBarChart(tool -> fail("generateComparisonCharts has been called"));
        toolScorecard.setToolReport(
                (currentTool, title, scorecardImageFile) -> fail("generateHtml has been called"));

        toolScorecard.generate(someTool);

        File[] files = requireNonNull(tmpDir.listFiles());
        assertEquals(0, files.length);
        assertFalse(toolBarChartCalled.get());
    }

    @Test
    void omitsToolTypeForCommercialToolsInAnonymousMode() throws IOException {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setAnonymousMode(true)
                        .build();

        BenchmarkScore.config = config;

        ToolScorecard toolScorecard =
                new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("Benchmark"));

        Tool someTool =
                ToolBuilder.builder()
                        .setIsCommercial(true)
                        .setTestSuiteResults(
                                TestSuiteResultsBuilder.builder()
                                        .setToolname("Some Tool")
                                        .setToolVersion("1.0")
                                        .setToolType(ToolType.SAST)
                                        .build())
                        .build();

        toolScorecard.setToolBarChart(tool -> {});

        toolScorecard.setToolReport((currentTool, title, scorecardImageFile) -> title);

        toolScorecard.generate(someTool);

        File[] files = requireNonNull(tmpDir.listFiles());

        Optional<File> htmlFile = fileWithEnding(files, "html");

        assertTrue(htmlFile.isPresent());
        String content = Files.readString(htmlFile.get().toPath());

        assertEquals("OWASP Benchmark Scorecard for Some Tool v1.0", content);
    }
}
