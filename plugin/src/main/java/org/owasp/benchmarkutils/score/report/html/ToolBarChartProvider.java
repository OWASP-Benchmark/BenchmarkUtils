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

import java.util.Collection;
import java.util.Map;
import org.owasp.benchmarkutils.score.CategoryMetrics;
import org.owasp.benchmarkutils.score.Tool;

public interface ToolBarChartProvider {

    /**
     * Generate Bar charts that compare a tool's Precision and Recall results to the average of all
     * the other tools and write those charts to tool/metric specific names.
     *
     * @param tool - The Tool to create the charts for.
     * @param toolCatMetrics - The metrics for the categories/category groups being charted.
     * @param overallAveToolMetrics The average metrics across all tools per the matching categories
     */
    void generateComparisonCharts(
            Tool tool,
            Collection<CategoryMetrics> toolCatMetrics,
            Map<String, CategoryMetrics> overallAveToolMetrics,
            boolean isCategoryGroups);
}
