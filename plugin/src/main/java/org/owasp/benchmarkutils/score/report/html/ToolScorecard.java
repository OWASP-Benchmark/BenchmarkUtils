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
import java.util.Collection;
import java.util.Map;
import org.owasp.benchmarkutils.helpers.CategoryGroups;
import org.owasp.benchmarkutils.score.CategoryMetrics;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;
import org.owasp.benchmarkutils.score.report.ScatterTools;
import org.owasp.benchmarkutils.score.report.ToolBarChart;
import org.owasp.benchmarkutils.score.report.ToolReport;

public class ToolScorecard {

    private final Map<String, CategoryMetrics> overallAveToolMetrics;
    private final File scoreCardDir;
    private final Configuration config;
    private final TestSuiteName testSuiteName;

    private ToolBarChartProvider toolBarChart;
    private ToolReportProvider toolReport;

    public ToolScorecard(
            Map<String, CategoryMetrics> overallAveToolMetrics,
            File scoreCardDir,
            Configuration config,
            TestSuiteName testSuiteName) {
        this.overallAveToolMetrics = overallAveToolMetrics;
        this.scoreCardDir = scoreCardDir;
        this.config = config;
        this.testSuiteName = testSuiteName;

        this.toolBarChart = new ToolBarChart(scoreCardDir);
        this.toolReport = new ToolReport(overallAveToolMetrics);
    }

    public void setToolReport(ToolReportProvider toolReport) {
        this.toolReport = toolReport;
    }

    /**
     * Generate a tool scorecard for the set of vulnerability metrics provided, which must match the
     * same type sent to the constructor for this class.
     *
     * @param tool The tool to score
     * @param toolCatMetrics The metrics to include for all the vuln categories
     */
    public void generate(Tool tool, Collection<CategoryMetrics> toolCatMetrics) {
        generate(tool, toolCatMetrics, false);
    }

    /**
     * Generate a tool scorecard for the set of metrics provided. The metrics provided vuln
     * categories, or category groups, must match the same type sent to the constructor for this
     * class.
     *
     * @param tool The tool to score
     * @param toolCatMetrics The metrics to include, for all the vuln categories, or category
     *     groups.
     * @param forCategoryGroups True if metrics are for CategoryGroups, false for vuln categories
     */
    public void generate(
            Tool tool, Collection<CategoryMetrics> toolCatMetrics, boolean forCategoryGroups) {
        if (config.showAveOnlyMode && tool.isCommercial()) {
            return;
        }

        toolBarChart.generateComparisonCharts(
                tool, toolCatMetrics, this.overallAveToolMetrics, forCategoryGroups);

        try {
            Files.write(
                    new File(reportPathFor(tool, forCategoryGroups)).toPath(),
                    reportHtml(tool, forCategoryGroups).getBytes());
            System.out.println("Scorecard written to: " + reportPathFor(tool, forCategoryGroups));
        } catch (Exception e) {
            System.out.println("Error creating and/or saving tool HTML scorecard!");
            e.printStackTrace();
        }
    }

    private String reportHtml(Tool tool, boolean forCategoryGroups) throws IOException {
        return toolReport.generateHtml(
                tool,
                titleFor(tool, forCategoryGroups),
                storedGraphFor(tool, forCategoryGroups),
                forCategoryGroups);
    }

    private String reportPathFor(Tool tool, boolean forCategoryGroups) {
        return scoreCardDir.getAbsolutePath()
                + File.separator
                + filenameFor(tool, forCategoryGroups)
                + ".html";
    }

    private String titleFor(Tool tool, boolean forCategoryGroups) {
        // default scorecard title
        String fullTitle =
                testSuiteName.fullName() + " Scorecard for " + tool.getToolNameAndVersion();

        if (CategoryGroups.isCategoryGroupsEnabled()) {
            if (forCategoryGroups) fullTitle += " per CWE Group";
            else fullTitle += " per CWE";
        }

        // If not in anonymous mode OR the tool is not commercial, add the type at the end of
        // the name. It's not added to anonymous commercial tools, because it would be redundant.
        if (!config.anonymousMode || !tool.isCommercial()) {
            fullTitle += " (" + tool.getToolType() + ")";
        }

        return fullTitle;
    }

    private File storedGraphFor(Tool tool, boolean forCategoryGroups) {
        String shortTitle =
                format(
                        "{0} v{1} Scorecard for {2}",
                        testSuiteName.simpleName(), tool.getTestSuiteVersion(), tool.getToolName());

        File img = new File(scoreCardDir, filenameFor(tool, forCategoryGroups) + ".png");

        try {
            graph(tool, shortTitle, forCategoryGroups).writeChartToFile(img, 800);
        } catch (IOException e) {
            System.out.println("Error saving tool Scatter chart to disk!");
            e.printStackTrace();
        }

        return img;
    }

    private ScatterTools graph(Tool tool, String shortTitle, boolean forCategoryGroups) {
        return new ScatterTools(shortTitle, 800, tool.getOverallMetrics(forCategoryGroups));
    }

    /**
     * Returns the name of the file that contains this tool's scorecard, without the file extension.
     * This version assumes there are no CategoryGroups defined.
     */
    public String filenameFor(Tool tool) {
        return filenameFor(tool, false);
    }

    /**
     * Returns the name of the file that contains this tool's scorecard, without the file extension.
     * This method supports creating a unique name for this file if CategoryGroups are being scored.
     */
    public String filenameFor(Tool tool, boolean forCategoryGroups) {
        return (format(
                                "{0} v{1} Scorecard for {2}",
                                testSuiteName.simpleName(),
                                tool.getTestSuiteVersion(),
                                tool.getToolNameAndVersion()))
                        .replace(' ', '_')
                + (forCategoryGroups ? "_groups" : "");
    }
}
