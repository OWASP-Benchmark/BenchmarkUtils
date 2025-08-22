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
import org.owasp.benchmarkutils.helpers.CategoryGroups;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;

public class MenuUpdater {

    private final Configuration config;
    private final TestSuiteName testSuite;
    private final String testSuiteVersion;
    private final CommercialAveragesTable commercialAveragesTable;
    private final Set<Tool> tools;
    private final Set<String> vulnCatSet;
    private final Set<String> categoryGroupSet;
    private final File scoreCardDir;
    private final ToolScorecard toolScorecard;
    private final boolean includeCategoryGroups;

    public MenuUpdater(
            Configuration config,
            TestSuiteName testSuite,
            String testSuiteVersion,
            CommercialAveragesTable commercialAveragesTable,
            Set<Tool> tools,
            Set<String> vulnCatSet,
            Set<String> categoryGroupSet,
            File scoreCardDir,
            ToolScorecard toolScorecard) {
        this.config = config;
        this.testSuite = testSuite;
        this.testSuiteVersion = testSuiteVersion;
        this.commercialAveragesTable = commercialAveragesTable;
        this.tools = tools;
        this.vulnCatSet = vulnCatSet;
        this.categoryGroupSet = categoryGroupSet;
        this.scoreCardDir = scoreCardDir;
        this.toolScorecard = toolScorecard;
        this.includeCategoryGroups = CategoryGroups.isCategoryGroupsEnabled();
    }

    /**
     * Updates the menus of all the scorecards previously generated so people can navigate between
     * all the tool results. Also perform a few other tag replacements for things that need to be
     * done in the final stages of scorecard generation.
     */
    public void updateMenus() {
        String toolMenu = toolMenu();
        String vulnerabilityMenu = vulnerabilityMenu();
        String toolCatalogGroupsMenu = toolCatalogGroupsMenu();
        String catalogGroupsMenu = catalogGroupsMenu();

        Arrays.stream(Objects.requireNonNull(scoreCardDir.listFiles()))
                .filter(MenuUpdater::isHtmlFile)
                .forEach(
                        f ->
                                updateMenuFor(
                                        f,
                                        toolMenu,
                                        vulnerabilityMenu,
                                        toolCatalogGroupsMenu,
                                        catalogGroupsMenu));
    }

    private String toolMenu() {
        StringBuilder sb = new StringBuilder();

        tools.stream()
                .filter(tool -> !(config.showAveOnlyMode && tool.isCommercial()))
                .forEach(tool -> sb.append(toolMenuEntry(tool, false)));

        if (commercialAveragesTable.hasEntries()) {
            sb.append(commercialAveragesMenuEntry(false));
        }

        return sb.toString();
    }

    private String toolCatalogGroupsMenu() {
        StringBuilder sb = new StringBuilder();
        if (this.includeCategoryGroups) {

            tools.stream()
                    .filter(tool -> !(config.showAveOnlyMode && tool.isCommercial()))
                    .forEach(tool -> sb.append(toolMenuEntry(tool, true)));

            if (commercialAveragesTable.hasEntries()) {
                sb.append(commercialAveragesMenuEntry(true));
            }
        }
        return sb.toString();
    }

    private String toolMenuEntry(Tool tool, boolean forCategoryGroups) {
        return format(
                "<li><a href=\"{0}.html\">{1}</a></li>{2}",
                toolScorecard.filenameFor(tool, forCategoryGroups),
                tool.getToolNameAndVersion(),
                System.lineSeparator());
    }

    private String commercialAveragesMenuEntry(boolean forCategoryGroups) {
        return format(
                "<li><a href=\"{0}\">Commercial Average</a></li>{1}",
                commercialAveragesTable.filename(forCategoryGroups), System.lineSeparator());
    }

    private String vulnerabilityMenu() {
        return vulnCatSet.stream().map(this::vulnerabilityMenuEntry).collect(Collectors.joining());
    }

    private String vulnerabilityMenuEntry(String cat) {
        return format(
                "<li><a href=\"{0}.html\">{1}</a></li>{2}",
                filenameFor(cat), cat, System.lineSeparator());
    }

    private String catalogGroupsMenu() {
        return categoryGroupSet.stream()
                .map(this::vulnerabilityMenuEntry)
                .collect(Collectors.joining());
    }

    private String filenameFor(String cat) {
        return format(
                "{0}_v{1}_Scorecard_for_{2}",
                testSuite.simpleName(), testSuiteVersion, cat.replace(' ', '_'));
    }

    private static boolean isHtmlFile(File f) {
        return !f.isDirectory() && f.getName().endsWith(".html");
    }

    private static final String TOOL_GROUPS_MENU =
            System.lineSeparator()
                    + "<li class=\"dropdown\"><a href=\"#\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" role=\"button\" "
                    + "aria-haspopup=\"true\" aria-expanded=\"false\">ToolsByGrp<span class=\"caret\"></span></a>"
                    + System.lineSeparator()
                    + "                        <ul class=\"dropdown-menu\">${toolgrpsmenu}"
                    + "                        </ul></li>";

    private static final String GROUPS_MENU =
            System.lineSeparator()
                    + "<li class=\"dropdown\"><a href=\"#\" class=\"dropdown-toggle\" data-toggle=\"dropdown\" role=\"button\" "
                    + "aria-haspopup=\"true\" aria-expanded=\"false\">CWE Groups<span class=\"caret\"></span></a>"
                    + System.lineSeparator()
                    + "                        <ul class=\"dropdown-menu\">${groupsmenu}"
                    + "                        </ul></li>";

    private void updateMenuFor(
            File f,
            String toolMenu,
            String vulnerabilityMenu,
            String toolCatalogGroupsMenu,
            String catalogGroupsMenu) {
        try {
            // The 2 Catalog Group menus are special cases. If these menu's are empty, we don't want
            // them to display at all, so we replace the tag with a blank string.
            // If they are not empty, we set all the HTML required to create the entire menu item
            toolCatalogGroupsMenu =
                    ((toolCatalogGroupsMenu.length() > 0)
                            ? TOOL_GROUPS_MENU.replace("${toolgrpsmenu}", toolCatalogGroupsMenu)
                            : "");
            catalogGroupsMenu =
                    ((catalogGroupsMenu.length() > 0)
                            ? GROUPS_MENU.replace("${groupsmenu}", catalogGroupsMenu)
                            : "");

            String html =
                    new String(Files.readAllBytes(f.toPath()))
                            .replace("${toolmenu}", toolMenu)
                            .replace("${vulnmenu}", vulnerabilityMenu)
                            .replace("${toolgrpsmenu}", toolCatalogGroupsMenu)
                            .replace("${groupsmenu}", catalogGroupsMenu)
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
