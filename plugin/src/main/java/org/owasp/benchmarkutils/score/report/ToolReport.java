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
 * @created 2015
 */
package org.owasp.benchmarkutils.score.report;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.DecimalFormat;
import java.util.Map;
import java.util.TreeMap;
import org.apache.commons.io.IOUtils;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.Category;
import org.owasp.benchmarkutils.helpers.CategoryGroups;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CategoryMetrics;
import org.owasp.benchmarkutils.score.TP_FN_TN_FP_Counts;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.ToolMetrics;
import org.owasp.benchmarkutils.score.report.ToolBarChart.BarChartType;
import org.owasp.benchmarkutils.score.report.html.ToolReportProvider;

public class ToolReport implements ToolReportProvider {

    private final Map<String, CategoryMetrics> overallAveToolMetricsMap;

    // Used for formatting percentage numbers in various generated tables
    private static final DecimalFormat decimPercentageFmt = new DecimalFormat("#0.00%");

    public ToolReport(Map<String, CategoryMetrics> overallAveToolMetricsMap) {
        this.overallAveToolMetricsMap = overallAveToolMetricsMap;
    }

    /**
     * Generate an HTML report for whatever tool's results are passed in.
     *
     * @param currentTool - the tool to generate a report for.
     * @param title - The title of the HTML report to generate.
     * @param scorecardImageFile - The File that contains the scorecard image for this tool's
     *     results.
     * @param forCategoryGroups True if generating results for CategoryGroups, false for normal vuln
     *     categories
     * @return The generated HTML report for the supplied tool.
     * @throws IOException
     */
    public String generateHtml(
            Tool currentTool, String title, File scorecardImageFile, boolean forCategoryGroups)
            throws IOException {

        ToolMetrics overallToolVulnMetrics = currentTool.getOverallMetrics(forCategoryGroups);

        // Resources in a jar file have to be loaded as streams. Not directly as Files.
        InputStream templateFileStream =
                ToolReport.class
                        .getClassLoader()
                        .getResourceAsStream(BenchmarkScore.SCORECARDDIRNAME + "/template.html");
        String html = IOUtils.toString(templateFileStream, StandardCharsets.UTF_8);

        html = html.replace("${testsuite}", BenchmarkScore.TESTSUITENAME.fullName());
        html = html.replace("${title}", title);
        html =
                html.replace(
                        "${tests}", Integer.toString(overallToolVulnMetrics.getTotalTestCases()));
        html = html.replace("${time}", overallToolVulnMetrics.getScanTime());
        html =
                html.replace(
                        "${score}",
                        decimPercentageFmt.format(overallToolVulnMetrics.getOverallScore()));
        html = html.replace("${tool}", currentTool.getToolName());
        html = html.replace("${version}", currentTool.getTestSuiteVersion());
        html = html.replace("${projectlink}", BenchmarkScore.config.report.html.projectLinkEntry);
        html = html.replace("${cwecategoryname}", BenchmarkScore.config.cweCategoryName);
        html = html.replace("${actualResultsFile}", currentTool.getActualResultsFileName());

        html = html.replace("${image}", scorecardImageFile.getName());
        String table =
                generateDetailedResultsTableForTool(
                        currentTool, overallAveToolMetricsMap, forCategoryGroups);
        html = html.replace("${table}", table);
        html = html.replace("${tprlabel}", BenchmarkScore.config.tprLabel);
        html =
                html.replace(
                        "${precisionkey}",
                        BenchmarkScore.config.report.html.precisionKeyEntry
                                + BenchmarkScore.config.report.html.fsCoreEntry);

        // Calculate the image tags for the Precision/Recall tables, if includePrecision enabled
        String precisionTablesVal =
                (BenchmarkScore.config.includePrecision
                        ? precisionTablesVal =
                                "<img align=\"middle\" src=\""
                                        + ToolBarChart.generateBarChartFileName(
                                                currentTool,
                                                BarChartType.Precision,
                                                forCategoryGroups)
                                        + "\" alt=\"\"/>\n<p />\n<p />\n"
                                        + "<img align=\"middle\" src=\""
                                        + ToolBarChart.generateBarChartFileName(
                                                currentTool, BarChartType.Recall, forCategoryGroups)
                                        + "\" alt=\"\"/>\n<p />\n<p />\n"
                        : "");

        // Remove or replace the placeholder for the optional Precision and Recall tables.
        html = html.replace("${precisiontables}", precisionTablesVal);

        return html;
    }

    /** Generate a Detailed results table for whatever tool's results are passed in. */
    private static String generateDetailedResultsTableForTool(
            Tool tool,
            Map<String, CategoryMetrics> overallAveToolMetrics,
            boolean forCategoryGroups) {
        StringBuilder sb = new StringBuilder();
        sb.append("<table class=\"table\">\n");
        sb.append("<tr>");
        if (CategoryGroups.isCategoryGroupsEnabled()) sb.append("<th>Group</th>");
        if (forCategoryGroups) sb.append("<th>Abbr.</th>");
        if (!forCategoryGroups) sb.append("<th>CWE Category</th>");
        if (!forCategoryGroups && BenchmarkScore.config.includePrecision)
            sb.append("<th>Abbr.</th>");
        if (!forCategoryGroups) sb.append("<th>CWE #</th>");
        sb.append("<th>TP</th>");
        sb.append("<th>FN</th>");
        sb.append("<th>TN</th>");
        sb.append("<th>FP</th>");
        sb.append("<th>Total</th>");
        if (BenchmarkScore.config.includePrecision) sb.append("<th>Precision</th><th>F-score</th>");
        sb.append("<th>${tprlabel}</th>");
        sb.append("<th>FPR</th>");
        sb.append("<th>Score</th>");
        sb.append("</tr>\n");
        TP_FN_TN_FP_Counts totals = new TP_FN_TN_FP_Counts();
        double totalPrecision = 0;
        double totalFScore = 0;
        double totalTPR = 0;
        double totalFPR = 0;
        double totalScore = 0;

        Map<String, String> outputLinePerCategory = new TreeMap<String, String>();
        Map<String, TP_FN_TN_FP_Counts> scoresPerCategory =
                tool.getCategoryScores(forCategoryGroups);
        for (String categoryName : scoresPerCategory.keySet()) {
            Category category = Categories.getCategoryByLongName(categoryName);

            TP_FN_TN_FP_Counts c = scoresPerCategory.get(categoryName);
            if (c == null) {
                new Exception(
                                "FATAL INTERNAL ERROR: No TP_FN_TN_FP_Counts found for: "
                                        + categoryName)
                        .printStackTrace();
                System.exit(-1);
            }

            CategoryMetrics categoryMetrics =
                    tool.getCategoryMetrics(categoryName, forCategoryGroups);
            if (categoryMetrics == null) {
                new Exception("FATAL INTERNAL ERROR: No CategoryMetrics found for: " + categoryName)
                        .printStackTrace();
                System.exit(-1);
            }

            String style = "";

            if (Math.abs(categoryMetrics.truePositiveRate - categoryMetrics.falsePositiveRate) < .1)
                style = "class=\"danger\"";
            else if (categoryMetrics.truePositiveRate > .7
                    && categoryMetrics.falsePositiveRate < .3) style = "class=\"success\"";

            // We use a lineBuff so we can sort the lines in different ways before output the table
            StringBuffer lineBuff = new StringBuffer();
            lineBuff.append("<tr " + style + ">");
            if (CategoryGroups.isCategoryGroupsEnabled()) {
                if (forCategoryGroups) {
                    lineBuff.append("<td>" + categoryName + "</td>");
                    lineBuff.append(
                            "<td>"
                                    + CategoryGroups.getCategoryGroupByName(categoryName)
                                            .getAbbrev()
                                    + "</td>");
                } else
                    lineBuff.append(
                            "<td>"
                                    + CategoryGroups.getCategoryGroupByCWE(category.getCWE())
                                            .getAbbrev()
                                    + "</td>");
            }
            if (!forCategoryGroups) lineBuff.append("<td>" + categoryName + "</td>");
            if (!forCategoryGroups && BenchmarkScore.config.includePrecision) { // Abbr. column
                lineBuff.append("<td>" + category.getShortName() + "</td>");
            }
            if (!forCategoryGroups) lineBuff.append("<td>" + category.getCWE() + "</td>");
            lineBuff.append("<td>" + c.tp + "</td>");
            lineBuff.append("<td>" + c.fn + "</td>");
            lineBuff.append("<td>" + c.tn + "</td>");
            lineBuff.append("<td>" + c.fp + "</td>");
            lineBuff.append("<td>" + categoryMetrics.totalTestCases + "</td>");
            String recallBonus = "";
            if (BenchmarkScore.config.includePrecision) {
                CategoryMetrics currentCategoryMetrics = overallAveToolMetrics.get(categoryName);
                if (currentCategoryMetrics == null) {
                    new Exception(
                                    "FATAL INTERNAL ERROR: currentCategoryMetrics is null for categoryName: "
                                            + categoryName)
                            .printStackTrace();
                    System.exit(-1);
                }
                // default value hard spaces equal to triangle width
                String precisionBonus = "&nbsp;&nbsp;&nbsp;&nbsp;";
                // r.precision has range 0-1, but currentCategoryMetrics.precision is 1 to 100.
                // FIXME: Fix precision calculations so they are the same units
                double precisionDiff =
                        100 * categoryMetrics.precision - currentCategoryMetrics.precision;
                if (precisionDiff >= 5)
                    precisionBonus =
                            "<span style=\"color: green\">&#9650;</span>"; // Green up triangle
                else if (precisionDiff <= -5) {
                    precisionBonus =
                            "<span style=\"color: red\">&#9660;</span>"; // Red down triangle
                }
                lineBuff.append(
                        "<td>"
                                + precisionBonus
                                + decimPercentageFmt.format(categoryMetrics.precision)
                                + "</td>");

                // default value hard spaces equal to triangle width
                String fscoreBonus = "&nbsp;&nbsp;&nbsp;&nbsp;";
                // FIXME: Fix F-score calculations so they are the same units
                double fscoreDiff = 100 * categoryMetrics.fscore - currentCategoryMetrics.fscore;
                if (fscoreDiff >= 5) fscoreBonus = "<span style=\"color: green\">&#9650;</span>";
                else if (fscoreDiff <= -5) {
                    fscoreBonus = "<span style=\"color: red\">&#9660;</span>";
                }
                lineBuff.append(
                        "<td>"
                                + fscoreBonus
                                + new DecimalFormat("#0.0000").format(categoryMetrics.fscore)
                                + "</td>");

                // default value hard spaces equal to triangle width
                recallBonus = "&nbsp;&nbsp;&nbsp;&nbsp;";
                // FIXME: Fix truePositiveRate calculations so they are the same units
                double recallDiff =
                        100 * categoryMetrics.truePositiveRate
                                - currentCategoryMetrics.truePositiveRate;
                if (recallDiff >= 5) recallBonus = "<span style=\"color: green\">&#9650;</span>";
                else if (recallDiff <= -5) {
                    recallBonus = "<span style=\"color: red\">&#9660;</span>";
                }
            }
            lineBuff.append(
                    "<td>"
                            + recallBonus
                            + decimPercentageFmt.format(categoryMetrics.truePositiveRate)
                            + "</td>");
            lineBuff.append(
                    "<td>"
                            + decimPercentageFmt.format(categoryMetrics.falsePositiveRate)
                            + "</td>");
            lineBuff.append("<td>" + decimPercentageFmt.format(categoryMetrics.score) + "</td>");
            lineBuff.append("</tr>\n");
            totals.tp += c.tp;
            totals.fn += c.fn;
            totals.tn += c.tn;
            totals.fp += c.fp;
            totalPrecision += categoryMetrics.precision;
            totalFScore += categoryMetrics.fscore;
            totalTPR += categoryMetrics.truePositiveRate;
            totalFPR += categoryMetrics.falsePositiveRate;
            totalScore += categoryMetrics.score;

            // If CategoryGroups is enabled, for the normal vulnerability report we append the Group
            // to the front of the category so the table is first sorted by CategroyGroup then
            // category name within that group
            if (!forCategoryGroups && CategoryGroups.isCategoryGroupsEnabled()) {
                outputLinePerCategory.put(
                        CategoryGroups.getCategoryGroupByCWE(category.getCWE()) + categoryName,
                        lineBuff.toString());
            } else outputLinePerCategory.put(categoryName, lineBuff.toString());
        }

        for (String line : outputLinePerCategory.values()) {
            sb.append(line);
        }

        sb.append("<tr><th>Totals</th>");
        if (CategoryGroups.isCategoryGroupsEnabled())
            sb.append("<th/>"); // If enabled, extra <th/> element is needed to align properly
        if (!forCategoryGroups)
            sb.append("<th/>"); // Category Groups don't include CWE column before
        if (!forCategoryGroups && BenchmarkScore.config.includePrecision)
            sb.append("<th/>"); // Abbr column added
        sb.append("<th>" + totals.tp + "</th>");
        sb.append("<th>" + totals.fn + "</th>");
        sb.append("<th>" + totals.tn + "</th>");
        sb.append("<th>" + totals.fp + "</th>");
        int total = totals.tp + totals.fn + totals.tn + totals.fp;
        sb.append("<th>" + total + "</th>");
        if (BenchmarkScore.config.includePrecision)
            sb.append("<th/><th/><th/><th/>"); // 4 columns added with this flag
        sb.append("<th/><th/><th/></tr>\n");

        sb.append("<tr><th>Overall Results*</th><th/><th/><th/><th/>");
        if (CategoryGroups.isCategoryGroupsEnabled())
            sb.append("<th/>"); // If enabled, extra element is needed so things align properly
        if (forCategoryGroups && !BenchmarkScore.config.includePrecision)
            sb.append("<th/>"); // For this combination, extra element also needed to align properly
        if (!forCategoryGroups)
            sb.append("<th/><th/>"); // Category Groups don't include 2 CWE columns before stats
        if (BenchmarkScore.config.includePrecision) {
            double precision = (totalPrecision / scoresPerCategory.size());
            sb.append("<th/><th>" + decimPercentageFmt.format(precision) + "</th>");
            double fscore = (totalFScore / scoresPerCategory.size());
            sb.append("<th>" + new DecimalFormat("#0.0000").format(fscore) + "</th>");
        }
        double tpr = (totalTPR / scoresPerCategory.size());
        sb.append("<th>" + decimPercentageFmt.format(tpr) + "</th>");
        double fpr = (totalFPR / scoresPerCategory.size());
        sb.append("<th>" + decimPercentageFmt.format(fpr) + "</th>");
        double score = totalScore / scoresPerCategory.size();
        sb.append("<th>" + decimPercentageFmt.format(score) + "</th>");
        sb.append("</tr>\n");
        if (BenchmarkScore.config.includePrecision) {
            sb.append(
                    "<tr><th colspan=\"3\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Legend:"
                            + "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;"
                            + "<span style=\"color: green\">&#9650;</span> = 5% or more above average</th>"
                            + "<th colspan=\"6\"><span style=\"color: red\">&#9660;</span> = 5% or more below average</th></tr>\n");
        }
        sb.append("</table>");
        sb.append(
                "<p>*-The Overall Results are averages across all the specified categories. "
                        + " You can't compute these averages by simply calculating the"
                        + (BenchmarkScore.config.includePrecision
                                ? " Precision, F-score, Recall (TPR),"
                                : " TPR")
                        + " and FPR rates using"
                        + " the values in the Totals row. If you did that, categories with larger number of tests would carry "
                        + " more weight than categories with less tests. The proper calculation of the Overall Results is to"
                        + " add up the values of each of these per row, "
                        + " then divide by the number of rows, which is how they are calculated.<p/>");

        return sb.toString();
    }
}
