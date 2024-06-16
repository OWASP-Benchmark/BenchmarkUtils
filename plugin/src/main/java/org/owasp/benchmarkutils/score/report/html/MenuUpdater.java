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

import static java.text.MessageFormat.format;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;

public class MenuUpdater {

    private final Configuration config;
    private final TestSuiteName testSuite;
    private final String testSuiteVersion;
    private final CommercialAveragesTable commercialAveragesTable;
    private final Set<Tool> tools;
    private final Set<String> catSet;
    private final File scoreCardDir;
    private final ToolScorecard toolScorecard;

    public MenuUpdater(
            Configuration config,
            TestSuiteName testSuite,
            String testSuiteVersion,
            CommercialAveragesTable commercialAveragesTable,
            Set<Tool> tools,
            Set<String> catSet,
            File scoreCardDir,
            ToolScorecard toolScorecard) {
        this.config = config;
        this.testSuite = testSuite;
        this.testSuiteVersion = testSuiteVersion;
        this.commercialAveragesTable = commercialAveragesTable;
        this.tools = tools;
        this.catSet = catSet;
        this.scoreCardDir = scoreCardDir;
        this.toolScorecard = toolScorecard;
    }

    /**
     * Updates the menus of all the scorecards previously generated so people can navigate between
     * all the tool results. Also perform a few other tag replacements for things that need to be
     * done in the final stages of scorecard generation.
     */
    public void updateMenus() {
        String toolMenu = toolMenu();
        String vulnerabilityMenu = vulnerabilityMenu();

        Arrays.stream(Objects.requireNonNull(scoreCardDir.listFiles()))
                .filter(MenuUpdater::isHtmlFile)
                .forEach(f -> updateMenuFor(f, toolMenu, vulnerabilityMenu));
    }

    private String toolMenu() {
        StringBuilder sb = new StringBuilder();

        tools.stream()
                .filter(tool -> !(config.showAveOnlyMode && tool.isCommercial()))
                .forEach(tool -> sb.append(toolMenuEntry(tool)));

        if (commercialAveragesTable.hasEntries()) {
            sb.append(commercialAveragesMenuEntry());
        }

        return sb.toString();
    }

    private String toolMenuEntry(Tool tool) {
        return format(
                "<li><a href=\"{0}.html\">{1}</a></li>{2}",
                toolScorecard.filenameFor(tool),
                tool.getToolNameAndVersion(),
                System.lineSeparator());
    }

    private String commercialAveragesMenuEntry() {
        return format(
                "<li><a href=\"{0}\">Commercial Average</a></li>{1}",
                commercialAveragesTable.filename(), System.lineSeparator());
    }

    private String vulnerabilityMenu() {
        return catSet.stream().map(this::vulnerabilityMenuEntry).collect(Collectors.joining());
    }

    private String vulnerabilityMenuEntry(String cat) {
        return format(
                "<li><a href=\"{0}.html\">{1}</a></li>{2}",
                filenameFor(cat), cat, System.lineSeparator());
    }

    private String filenameFor(String cat) {
        return format(
                "{0}_v{1}_Scorecard_for_{2}",
                testSuite.simpleName(), testSuiteVersion, cat.replace(' ', '_'));
    }

    private static boolean isHtmlFile(File f) {
        return !f.isDirectory() && f.getName().endsWith(".html");
    }

    private void updateMenuFor(File f, String toolMenu, String vulnerabilityMenu) {
        try {
            String html =
                    new String(Files.readAllBytes(f.toPath()))
                            .replace("${toolmenu}", toolMenu)
                            .replace("${vulnmenu}", vulnerabilityMenu)
                            .replace("${testsuite}", testSuite.fullName())
                            .replace("${version}", testSuiteVersion)
                            .replace("${projectlink}", config.report.html.projectLinkEntry)
                            .replace("${cwecategoryname}", config.cweCategoryName)
                            .replace(
                                    "${precisionkey}",
                                    config.report.html.precisionKeyEntry
                                            + config.report.html.fsCoreEntry);

            Files.write(f.toPath(), html.getBytes());
        } catch (IOException e) {
            System.out.println("Error updating menus in: " + f.getName());
            e.printStackTrace();
        }
    }
}
