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
import java.util.Map;
import org.owasp.benchmarkutils.score.CategoryResults;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;
import org.owasp.benchmarkutils.score.report.ScatterTools;
import org.owasp.benchmarkutils.score.report.ToolBarChart;
import org.owasp.benchmarkutils.score.report.ToolReport;

public class ToolScorecard {

    private final File scoreCardDir;
    private final Configuration config;
    private final TestSuiteName testSuiteName;

    private ToolBarChartProvider toolBarChart;
    private ToolReportProvider toolReport;

    public ToolScorecard(
            Map<String, CategoryResults> overallAveToolResults,
            File scoreCardDir,
            Configuration config,
            TestSuiteName testSuiteName) {
        this.scoreCardDir = scoreCardDir;
        this.config = config;
        this.testSuiteName = testSuiteName;

        this.toolBarChart = new ToolBarChart(overallAveToolResults, scoreCardDir);
        this.toolReport = new ToolReport(overallAveToolResults);
    }

    public void setToolBarChart(ToolBarChartProvider toolBarChart) {
        this.toolBarChart = toolBarChart;
    }

    public void setToolReport(ToolReportProvider toolReport) {
        this.toolReport = toolReport;
    }

    public void generate(Tool tool) {
        if (config.showAveOnlyMode && tool.isCommercial()) {
            return;
        }

        toolBarChart.generateComparisonCharts(tool);

        try {
            Files.write(new File(reportPathFor(tool)).toPath(), reportHtml(tool).getBytes());
            System.out.println("Scorecard written to: " + reportPathFor(tool));
        } catch (Exception e) {
            System.out.println("Error creating and/or saving tool HTML scorecard!");
            e.printStackTrace();
        }
    }

    private String reportHtml(Tool tool) throws IOException {
        return toolReport.generateHtml(tool, titleFor(tool), storedGraphFor(tool));
    }

    private String reportPathFor(Tool tool) {
        return scoreCardDir.getAbsolutePath() + File.separator + filenameFor(tool) + ".html";
    }

    private String titleFor(Tool tool) {
        String fullTitle =
                testSuiteName.fullName() + " Scorecard for " + tool.getToolNameAndVersion();

        // If not in anonymous mode OR the tool is not commercial, add the type at the end of
        // the name. It's not added to anonymous commercial tools, because it would be
        // redundant.
        if (!config.anonymousMode || !tool.isCommercial()) {
            fullTitle += " (" + tool.getToolType() + ")";
        }

        return fullTitle;
    }

    private File storedGraphFor(Tool tool) {
        String shortTitle =
                format(
                        "{0} v{1} Scorecard for {2}",
                        testSuiteName.simpleName(), tool.getTestSuiteVersion(), tool.getToolName());

        File img = new File(scoreCardDir, filenameFor(tool) + ".png");

        try {
            graph(tool, shortTitle).writeChartToFile(img, 800);
        } catch (IOException e) {
            System.out.println("Error saving tool Scatter chart to disk!");
            e.printStackTrace();
        }

        return img;
    }

    private ScatterTools graph(Tool tool, String shortTitle) {
        return new ScatterTools(shortTitle, 800, tool.getOverallResults());
    }

    /**
     * Returns the name of the file that contains this tool's scorecard, without the file extension.
     */
    public String filenameFor(Tool tool) {
        return (format(
                        "{0} v{1} Scorecard for {2}",
                        testSuiteName.simpleName(),
                        tool.getTestSuiteVersion(),
                        tool.getToolNameAndVersion()))
                .replace(' ', '_');
    }
}
