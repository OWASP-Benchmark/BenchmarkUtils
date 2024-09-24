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
 * @author Dave Wichers
 * @created 2021
 */
package org.owasp.benchmarkutils.score.report;

import java.awt.BasicStroke;
import java.awt.Color;
import java.io.File;
import java.io.IOException;
import java.util.Collection;
import java.util.Map;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.axis.NumberAxis;
import org.jfree.chart.axis.NumberTickUnit;
import org.jfree.chart.plot.CategoryPlot;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.category.CategoryItemRenderer;
import org.jfree.chart.ui.RectangleInsets;
import org.jfree.data.category.DefaultCategoryDataset;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.CategoryGroups;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CategoryMetrics;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.report.html.ToolBarChartProvider;

/** Used by ToolScorecard to generate a BarChart when desired. */
public class ToolBarChart extends ScatterPlot implements ToolBarChartProvider {

    private static final Color BLUECOLUMN = Color.decode("#4572a7"); // Blue
    private static final Color PURPLECOLUMN = Color.decode("#7851a9"); // Royal purple

    private final File scoreCardDir;

    enum BarChartType {
        Precision,
        Recall
    }

    /**
     * Initialize the data required to generate a ToolBarChart.
     *
     * @param scoreCardDir The directory to write the generated chart to.
     */
    public ToolBarChart(File scoreCardDir) {
        this.scoreCardDir = scoreCardDir;
    }

    private static void initializePlot(
            JFreeChart chart, DefaultCategoryDataset dataset, Color toolColor) {
        CategoryPlot xyplot = chart.getCategoryPlot();
        CategoryItemRenderer renderer = xyplot.getRendererForDataset(dataset);
        renderer.setSeriesPaint(0, toolColor); // Set tool column color
        renderer.setSeriesPaint(1, new Color(190, 190, 190)); // Set gray column color
        renderer.setDefaultOutlinePaint(new Color(0, 0, 0)); // Set black column border

        NumberAxis rangeAxis = (NumberAxis) xyplot.getRangeAxis();

        rangeAxis.setRange(0, 100);
        rangeAxis.setNumberFormatOverride(TABLE_PCT_FORMAT);
        rangeAxis.setTickLabelPaint(Color.decode("#666666"));
        rangeAxis.setMinorTickCount(5);
        rangeAxis.setTickUnit(new NumberTickUnit(10));
        rangeAxis.setAxisLineVisible(true);
        rangeAxis.setMinorTickMarksVisible(true);
        rangeAxis.setTickMarksVisible(true);
        rangeAxis.setLowerMargin(10);
        rangeAxis.setUpperMargin(10);

        xyplot.setRangeGridlineStroke(new BasicStroke());
        xyplot.setRangeGridlinePaint(Color.lightGray);
        xyplot.setRangeMinorGridlinePaint(Color.decode("#DDDDDD"));
        xyplot.setRangeMinorGridlinesVisible(true);
        xyplot.setOutlineVisible(true);
        xyplot.setDomainGridlineStroke(new BasicStroke());
        xyplot.setDomainGridlinePaint(Color.lightGray);

        BarRenderer brenderer = (BarRenderer) xyplot.getRenderer();
        brenderer.setItemMargin(0); // Eliminate space between bars within vuln category

        chart.setTextAntiAlias(true);
        chart.setAntiAlias(true);
        chart.setPadding(new RectangleInsets(20, 20, 0, 20));
    }

    /**
     * Create a BarChart of the specified type and store it in a file in the specified directory.
     *
     * @param tool - The tool to create the chart for.
     * @param dataset - The dataset that contains this tool's results and the results to compare it
     *     to.
     * @param type - The Type of BarChart to create.
     * @param isCategoryGroups True if chart is for CategoryGroups, false for vuln categories
     */
    private void createBarChart(
            Tool tool,
            DefaultCategoryDataset dataset,
            BarChartType type,
            boolean isCategoryGroups) {

        JFreeChart chart =
                ChartFactory.createBarChart(
                        tool.getToolNameAndVersion()
                                + " "
                                + type.name()
                                + " Results per CWE"
                                + (isCategoryGroups ? " Group" : ""), // TODO: Make Configurable
                        "",
                        type.name(),
                        dataset,
                        PlotOrientation.VERTICAL,
                        true,
                        false,
                        false);
        theme.apply(chart);

        switch (type) {
            case Precision:
                initializePlot(chart, dataset, BLUECOLUMN);
                break;
            case Recall:
                initializePlot(chart, dataset, PURPLECOLUMN);
                break;
        }

        String fileToCreate = generateBarChartFileName(tool, type, isCategoryGroups);
        File barChartFile = new File(this.scoreCardDir, fileToCreate);
        try {
            writeChartToFile(barChartFile, chart, 800);
        } catch (IOException e) {
            System.out.println("Error writing bar chart to target file.");
            e.printStackTrace();
        }
    }

    /**
     * createBarChart() uses this method to create the filenames for the generated .png files. So
     * you can invoke this again outside the class to get the name of the generated file.
     *
     * @param tool - The tool to generate the Bar chart for.
     * @param type - The type of Bar chart to create.
     * @param isCategoryGroups True if the chart is for CategoryGroups, false if for vuln categories
     * @return - The filename to write this type of Bar chart to.
     */
    public static String generateBarChartFileName(
            Tool tool, BarChartType type, boolean isCategoryGroups) {
        String filename =
                BenchmarkScore.TESTSUITENAME.simpleName()
                        + " v"
                        + tool.getTestSuiteVersion()
                        + " "
                        + type.name()
                        + " Chart for "
                        + tool.getToolNameAndVersion()
                        + (isCategoryGroups ? "_groups" : "")
                        + ".png";
        filename = filename.replace(' ', '_');
        return filename;
    }

    /**
     * Create a jFree chart DataSet that contains the scores per category for 1 tool, and the
     * average scores across all tools.
     *
     * @param targetTool - The tool to create the chart for.
     * @param toolCatMetrics - The metrics for the categories/category groups being charted.
     * @param overallAveToolMetrics The average metrics across all tools per the matching categories
     * @param isCategoryGroups True if metrics are for CategoryGroups, false for vuln categories
     * @param type - The Type of Bar Chart to create.
     * @return The created DataSet.
     */
    private DefaultCategoryDataset createToolDataSet(
            Tool targetTool,
            Collection<CategoryMetrics> toolCatMetrics,
            Map<String, CategoryMetrics> overallAveToolMetrics,
            boolean isCategoryGroups,
            BarChartType type) {
        final DefaultCategoryDataset dataset = new DefaultCategoryDataset();

        final String TOOLNAME = targetTool.getToolNameAndVersion();

        for (CategoryMetrics catResults : toolCatMetrics) {
            double data = -1.0;
            switch (type) {
                case Precision:
                    data = catResults.precision;
                    break;
                case Recall:
                    data = catResults.truePositiveRate;
                    break;
            }
            dataset.addValue(
                    data * 100,
                    TOOLNAME,
                    (isCategoryGroups
                            ? CategoryGroups.getCategoryGroupByName(catResults.category).getAbbrev()
                            : Categories.getCategoryByLongName(catResults.category)
                                    .getShortName()));
        }

        Collection<CategoryMetrics> aveCatMetrics = overallAveToolMetrics.values();
        for (CategoryMetrics catResults : aveCatMetrics) {

            double data = -1.0;
            switch (type) {
                case Precision:
                    data = catResults.precision;
                    break;
                case Recall:
                    data = catResults.truePositiveRate;
                    break;
            }
            dataset.addValue(
                    data * 100,
                    "Average",
                    (isCategoryGroups
                            ? CategoryGroups.getCategoryGroupByName(catResults.category).getAbbrev()
                            : Categories.getCategoryByLongName(catResults.category)
                                    .getShortName()));
        }

        return dataset;
    }

    /**
     * Generate Bar charts that compare a tool's Precision and Recall results to the average of all
     * the other tools and write those charts to tool/metric specific names.
     *
     * @param tool - The Tool to create the charts for.
     * @param toolCatMetrics - The metrics for the categories/category groups being charted.
     * @param overallAveToolMetrics The average metrics across all tools per the matching categories
     * @param isCategoryGroups True if metrics are for CategoryGroups, false for vuln categories
     */
    public void generateComparisonCharts(
            Tool tool,
            Collection<CategoryMetrics> toolCatMetrics,
            Map<String, CategoryMetrics> overallAveToolMetrics,
            boolean isCategoryGroups) {

        if (BenchmarkScore.config.includePrecision) {
            // Generate Precision Chart
            // First create the Dataset required for the chart
            DefaultCategoryDataset toolPrecisionData =
                    createToolDataSet(
                            tool,
                            toolCatMetrics,
                            overallAveToolMetrics,
                            isCategoryGroups,
                            ToolBarChart.BarChartType.Precision);
            // Then create the chart and write it to disk
            this.createBarChart(
                    tool, toolPrecisionData, ToolBarChart.BarChartType.Precision, isCategoryGroups);

            // Generate Recall Chart and write it to disk
            DefaultCategoryDataset toolRecallData =
                    createToolDataSet(
                            tool,
                            toolCatMetrics,
                            overallAveToolMetrics,
                            isCategoryGroups,
                            ToolBarChart.BarChartType.Recall);
            this.createBarChart(
                    tool, toolRecallData, ToolBarChart.BarChartType.Recall, isCategoryGroups);
        }
    }
}
