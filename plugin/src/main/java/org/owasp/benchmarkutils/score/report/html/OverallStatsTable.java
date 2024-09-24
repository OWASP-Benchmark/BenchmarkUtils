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

import static org.owasp.benchmarkutils.score.report.Formats.fourDecimalPlacesNumber;
import static org.owasp.benchmarkutils.score.report.Formats.twoDecimalPlacesPercentage;

import java.util.Set;
import org.owasp.benchmarkutils.score.Configuration;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.ToolMetrics;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;

public class OverallStatsTable {

    private final Configuration config;
    private final TestSuiteName testSuiteName;

    public OverallStatsTable(Configuration config, TestSuiteName testSuiteName) {
        this.config = config;
        this.testSuiteName = testSuiteName;
    }

    /**
     * Generate the overall stats table across all the tools for the bottom of the home page.
     *
     * @param tools - The set of all tools being scored. Each Tool includes it's scored results.
     * @return The HTML of the overall stats table.
     */
    public String generateFor(Set<Tool> tools) {
        HtmlStringBuilder htmlBuilder = new HtmlStringBuilder();

        htmlBuilder.beginTable("table");

        addHeaderTo(htmlBuilder);

        tools.stream()
                .filter(tool -> !(config.showAveOnlyMode && tool.isCommercial()))
                .forEach(tool -> appendRowTo(htmlBuilder, tool));

        htmlBuilder.endTable();

        htmlBuilder.p(
                "*-Please refer to each tool's scorecard for the data used to calculate these values.");

        return htmlBuilder.toString();
    }

    private void addHeaderTo(HtmlStringBuilder htmlBuilder) {
        htmlBuilder.beginTr();
        htmlBuilder.th("Tool");

        if (config.mixedMode) {
            htmlBuilder.th(testSuiteName.simpleName() + " Version");
        }

        htmlBuilder.th("Type");

        if (config.includePrecision) {
            htmlBuilder.th("Precision*");
            htmlBuilder.th("F-score*");
        }

        htmlBuilder.th("${tprlabel}*");
        htmlBuilder.th("FPR*");
        htmlBuilder.th("Score*");

        htmlBuilder.endTr();
    }

    private void appendRowTo(HtmlStringBuilder htmlBuilder, Tool tool) {
        ToolMetrics metrics = tool.getOverallMetrics();

        htmlBuilder.beginTr(cssClassFor(metrics));
        htmlBuilder.td(tool.getToolNameAndVersion());

        if (config.mixedMode) {
            htmlBuilder.td(tool.getTestSuiteVersion());
        }

        htmlBuilder.td(tool.getToolType().name());

        if (config.includePrecision) {
            htmlBuilder
                    .td(twoDecimalPlacesPercentage.format(metrics.getPrecision()))
                    .td(fourDecimalPlacesNumber.format(metrics.getFScore()));
        }

        htmlBuilder
                .td(twoDecimalPlacesPercentage.format(metrics.getTruePositiveRate()))
                .td(twoDecimalPlacesPercentage.format(metrics.getFalsePositiveRate()))
                .td(twoDecimalPlacesPercentage.format(metrics.getOverallScore()))
                .endTr();
    }

    private String cssClassFor(ToolMetrics metrics) {
        String cssClass = null;

        if (isDanger(metrics)) {
            cssClass = "danger";
        } else if (isSuccess(metrics)) {
            cssClass = "success";
        }

        return cssClass;
    }

    private boolean isSuccess(ToolMetrics metrics) {
        return metrics.getTruePositiveRate() > .7 && metrics.getFalsePositiveRate() < .3;
    }

    private boolean isDanger(ToolMetrics metrics) {
        return Math.abs(metrics.getTruePositiveRate() - metrics.getFalsePositiveRate()) < .1;
    }
}
