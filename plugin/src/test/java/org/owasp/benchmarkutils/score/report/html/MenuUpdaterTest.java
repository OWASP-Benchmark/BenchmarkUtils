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
import static java.util.Collections.emptySet;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CategoryResults;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.builder.ConfigurationBuilder;
import org.owasp.benchmarkutils.score.builder.TestSuiteResultsBuilder;
import org.owasp.benchmarkutils.score.builder.ToolBuilder;
import org.owasp.benchmarkutils.score.builder.ToolResultsBuilder;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;
import org.owasp.benchmarkutils.score.report.ScatterVulns;

class MenuUpdaterTest {

    private File tmpDir;

    @BeforeEach
    void setUp() throws IOException {
        tmpDir = Files.createTempDirectory("Benchmark.MenuUpdaterTest").toFile();
    }

    @Test
    void updatesMenusInHtmlFiles() throws IOException {
        Configuration config =
                ConfigurationBuilder.builder()
                        .setShowAveOnlyMode(false)
                        .setIncludeProjectLink(true)
                        .setIncludePrecision(true)
                        .setCweCategoryName("Some Category")
                        .setReportHtmlProjectLinkEntry("<p>Project Link Entry</p>")
                        .setReportHtmlPrecisionKeyEntry("<p>Precision Key Entry</p>")
                        .setReportHtmlFsCoreEntry("<p>FS Core Entry</p>")
                        .build();
        BenchmarkScore.config = config;
        Tool firstTool = freeToolWithName("Tool A");
        Tool secondTool = freeToolWithName("Tool B");

        TestSuiteName testSuite = new TestSuiteName("Benchmark");

        MenuUpdater menuUpdater =
                new MenuUpdater(
                        config,
                        testSuite,
                        "1.2",
                        emptyCommercialAveragesTable(),
                        asSet(firstTool, secondTool),
                        asSet("Path Traversal", "Command Injection"),
                        tmpDir,
                        new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("")) {
                            @Override
                            public String filenameFor(Tool tool) {
                                return "filename-for-" + tool.getToolName();
                            }
                        });

        writeDummyHtmlTo("some-file.html", "some header");
        writeDummyHtmlTo("another-file.html", "another header");

        menuUpdater.updateMenus();

        String firstFile = Files.readString(pathToFile("some-file.html"));
        String secondFile = Files.readString(pathToFile("another-file.html"));

        assertTrue(firstFile.contains("some header"));
        assertTrue(secondFile.contains("another header"));

        asSet(firstFile, secondFile)
                .forEach(
                        file -> {
                            assertTrue(file.contains("${dontreplace}"));

                            assertFalse(file.contains("${toolmenu}"));
                            assertTrue(
                                    file.contains(
                                            "<li><a href=\"filename-for-Tool A.html\">Tool A v47.11</a></li>"));
                            assertTrue(
                                    file.contains(
                                            "<li><a href=\"filename-for-Tool B.html\">Tool B v47.11</a></li>"));
                            assertFalse(file.contains("Commercial Average"));

                            assertFalse(file.contains("${vulnmenu}"));
                            assertTrue(
                                    file.contains(
                                            "<li><a href=\"Benchmark_v1.2_Scorecard_for_Path_Traversal.html\">Path Traversal</a></li>"));
                            assertTrue(
                                    file.contains(
                                            "<li><a href=\"Benchmark_v1.2_Scorecard_for_Command_Injection.html\">Command Injection</a></li>"));

                            assertFalse(file.contains("${testsuite}"));
                            assertTrue(file.contains("testsuite=OWASP Benchmark"));

                            assertFalse(file.contains("${version}"));
                            assertTrue(file.contains("version=1.2"));

                            assertFalse(file.contains("${projectlink}"));
                            assertTrue(file.contains("<p>Project Link Entry</p>"));

                            assertFalse(file.contains("${cwecategoryname}"));
                            assertTrue(file.contains("Some Category"));

                            assertFalse(file.contains("${precisionkey}"));
                            assertTrue(
                                    file.contains(
                                            "<p>Precision Key Entry</p><p>FS Core Entry</p>"));
                        });
    }

    private static Tool freeToolWithName(String toolName) {
        return toolWithName(toolName, false);
    }

    private static Tool toolWithName(String toolName, boolean isCommercial) {
        return ToolBuilder.builder()
                .setIsCommercial(isCommercial)
                .setTestSuiteResults(
                        TestSuiteResultsBuilder.builder()
                                .setIsCommercial(isCommercial)
                                .setToolname(toolName)
                                .build())
                .build();
    }

    private static Tool commercialToolWithName(String toolName) {
        return toolWithName(toolName, true);
    }

    private static CommercialAveragesTable emptyCommercialAveragesTable() {
        return new CommercialAveragesTable(new TestSuiteName(""), "") {};
    }

    private void writeDummyHtmlTo(String child, String header) throws IOException {
        Files.writeString(
                pathToFile(child),
                header
                        + "\n"
                        + "${dontreplace}\n"
                        + "${toolmenu}\n"
                        + "${vulnmenu}\n"
                        + "testsuite=${testsuite}\n"
                        + "version=${version}\n"
                        + "${projectlink}\n"
                        + "${cwecategoryname}\n"
                        + "${precisionkey}");
    }

    private Path pathToFile(String child) {
        return new File(tmpDir, child).toPath();
    }

    private Set<Tool> asSet(Tool... tools) {
        return Arrays.stream(tools).collect(Collectors.toSet());
    }

    private Set<String> asSet(String... strings) {
        return Arrays.stream(strings).collect(Collectors.toSet());
    }

    @Test
    void doesNotUpdateNonHtmlFiles() throws IOException {
        Configuration config = ConfigurationBuilder.builder().build();
        BenchmarkScore.config = config;

        MenuUpdater menuUpdater =
                new MenuUpdater(
                        config,
                        new TestSuiteName(""),
                        "",
                        emptyCommercialAveragesTable(),
                        emptySet(),
                        emptySet(),
                        tmpDir,
                        new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("")));

        writeDummyHtmlTo("some-file.txt", "some header");

        menuUpdater.updateMenus();

        String file = Files.readString(pathToFile("some-file.txt"));

        assertTrue(file.contains("${dontreplace}"));
        assertTrue(file.contains("${toolmenu}"));
        assertTrue(file.contains("${vulnmenu}"));
        assertTrue(file.contains("${testsuite}"));
        assertTrue(file.contains("${version}"));
        assertTrue(file.contains("${projectlink}"));
        assertTrue(file.contains("${cwecategoryname}"));
        assertTrue(file.contains("${precisionkey}"));
    }

    @Test
    void doesNotUpdateDirectories() {
        Configuration config = ConfigurationBuilder.builder().build();
        BenchmarkScore.config = config;

        MenuUpdater menuUpdater =
                new MenuUpdater(
                        config,
                        new TestSuiteName(""),
                        "",
                        emptyCommercialAveragesTable(),
                        emptySet(),
                        emptySet(),
                        tmpDir,
                        new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("")));

        assertTrue(new File(tmpDir, "some-dir.html").mkdir());

        assertDoesNotThrow(menuUpdater::updateMenus);
    }

    @Test
    void createsLinkToCommercialAveragesTable() throws IOException {
        Configuration config = ConfigurationBuilder.builder().build();
        BenchmarkScore.config = config;

        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(new TestSuiteName("Benchmark"), "1.2");

        Set<Tool> tools =
                asSet(
                        ToolBuilder.builder()
                                .setIsCommercial(true)
                                .setToolResults(
                                        ToolResultsBuilder.builder()
                                                .addCategoryResult(
                                                        new CategoryResults("", 0, 0, 0, 0))
                                                .build())
                                .build());

        commercialAveragesTable.add(new ScatterVulns("", 0, "", tools, null));

        MenuUpdater menuUpdater =
                new MenuUpdater(
                        config,
                        new TestSuiteName(""),
                        "",
                        commercialAveragesTable,
                        emptySet(),
                        emptySet(),
                        tmpDir,
                        new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("")) {
                            @Override
                            public String filenameFor(Tool tool) {
                                return "filename-for-" + tool.getToolName();
                            }
                        });

        writeDummyHtmlTo("some-file.html", "some header");

        menuUpdater.updateMenus();

        String file = Files.readString(pathToFile("some-file.html"));

        assertTrue(
                file.contains(
                        "<li><a href=\"Benchmark_v1.2_Scorecard_for_Commercial_Tools.html\">Commercial Average</a></li>"));
    }

    @Test
    void createsLinkToCommercialToolWhenNotInAverageMode() throws IOException {
        Configuration config = ConfigurationBuilder.builder().setShowAveOnlyMode(false).build();
        BenchmarkScore.config = config;

        MenuUpdater menuUpdater =
                new MenuUpdater(
                        config,
                        new TestSuiteName(""),
                        "",
                        emptyCommercialAveragesTable(),
                        asSet(freeToolWithName("Tool A"), commercialToolWithName("Tool B")),
                        emptySet(),
                        tmpDir,
                        new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("")) {
                            @Override
                            public String filenameFor(Tool tool) {
                                return "filename-for-" + tool.getToolName();
                            }
                        });

        writeDummyHtmlTo("some-file.html", "some header");

        menuUpdater.updateMenus();

        String file = Files.readString(pathToFile("some-file.html"));

        assertTrue(
                file.contains("<li><a href=\"filename-for-Tool A.html\">Tool A v47.11</a></li>"));
        assertTrue(
                file.contains("<li><a href=\"filename-for-Tool B.html\">Tool B v47.11</a></li>"));
    }

    @Test
    void omitsLinkToCommercialToolWhenInAverageMode() throws IOException {
        Configuration config = ConfigurationBuilder.builder().setShowAveOnlyMode(true).build();
        BenchmarkScore.config = config;

        MenuUpdater menuUpdater =
                new MenuUpdater(
                        config,
                        new TestSuiteName(""),
                        "",
                        emptyCommercialAveragesTable(),
                        asSet(freeToolWithName("Tool A"), commercialToolWithName("Tool B")),
                        emptySet(),
                        tmpDir,
                        new ToolScorecard(emptyMap(), tmpDir, config, new TestSuiteName("")) {
                            @Override
                            public String filenameFor(Tool tool) {
                                return "filename-for-" + tool.getToolName();
                            }
                        });

        writeDummyHtmlTo("some-file.html", "some header");

        menuUpdater.updateMenus();

        String file = Files.readString(pathToFile("some-file.html"));

        assertTrue(
                file.contains("<li><a href=\"filename-for-Tool A.html\">Tool A v47.11</a></li>"));
        assertFalse(
                file.contains("<li><a href=\"filename-for-Tool B.html\">Tool B v47.11</a></li>"));
    }
}
