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
package org.owasp.benchmarkutils.score;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.CategoryGroups;
import org.owasp.benchmarkutils.score.TestSuiteResults.ToolType;

/**
 * This class contains all the details for a specific tool, including all the results scored for the
 * tool. A side effect of creating an instance of Tool is that the HTML report for this tool, and
 * the .csv actual results files are both created to support scorecard generation.
 */
public class Tool implements Comparable<Tool> {

    private final boolean isCommercial;
    private final ToolType toolType;
    private String toolName = "not specified";
    private final String toolNameAndVersion;
    private final String testSuiteVersion;
    private final Map<String, TP_FN_TN_FP_Counts>
            categoryScores; // This tool's scores per vuln category.
    private final Map<String, TP_FN_TN_FP_Counts>
            categoryGroupScores; // If enabled, this tool's scores per CategoryGroup.
    private final Map<String, CategoryMetrics>
            categoryGroupMetrics; // If enabled, this tool's Metrics per CategoryGroup.
    private final TestSuiteResults actualResults;
    private final ToolMetrics
            overallVulnMetrics; // The metrics for each vulnerability category for this tool.
    private final ToolMetrics overallCategoryGroupMetrics; // If enabled, this
    // tool's CategoryMetrics per CategoryGroup.
    private final String actualResultsFileName; // Name of this tool's .csv computed results file

    public Tool(
            TestSuiteResults actualResults,
            Map<String, TP_FN_TN_FP_Counts> scores,
            ToolMetrics toolVulnMetrics,
            String actualCSVResultsFileName,
            boolean isCommercial) {

        this.isCommercial = isCommercial;
        this.toolType = actualResults.toolType;
        this.toolName = actualResults.getToolName();
        this.toolNameAndVersion = actualResults.getToolNameAndVersion();
        this.testSuiteVersion = actualResults.getTestSuiteVersion();

        this.categoryScores = scores;
        if (CategoryGroups.isCategoryGroupsEnabled()) {
            this.categoryGroupScores = new TreeMap<String, TP_FN_TN_FP_Counts>();
            for (Map.Entry<String, TP_FN_TN_FP_Counts> categoryScore : categoryScores.entrySet()) {
                String category = categoryScore.getKey();
                int cweNum = Categories.getCategoryByLongName(category).getCWE();
                String categoryGroupLongname =
                        CategoryGroups.getCategoryGroupByCWE(cweNum).getLongName();
                TP_FN_TN_FP_Counts categoryGroupCounts =
                        this.categoryGroupScores.get(categoryGroupLongname);
                if (categoryGroupCounts == null) {
                    categoryGroupCounts = new TP_FN_TN_FP_Counts();
                    this.categoryGroupScores.put(categoryGroupLongname, categoryGroupCounts);
                }
                TP_FN_TN_FP_Counts categoryScoreCounts = categoryScore.getValue();
                categoryGroupCounts.fn += categoryScoreCounts.fn;
                categoryGroupCounts.fp += categoryScoreCounts.fp;
                categoryGroupCounts.tn += categoryScoreCounts.tn;
                categoryGroupCounts.tp += categoryScoreCounts.tp;
            }

            // Now that we have the TP_FN_TN_FP_Counts per CategoryGroup, we calculate the
            // CategoryMetrics for each CategoryGroup and the overall metrics too
            this.overallCategoryGroupMetrics = new ToolMetrics();
            double totalFPRate = 0;
            double totalTPRate = 0;
            int total = 0;
            int totalTP = 0;
            int totalFP = 0;
            int totalFN = 0;
            int totalTN = 0;

            this.categoryGroupMetrics = new TreeMap<String, CategoryMetrics>();
            for (String categoryGroupLongname : this.categoryGroupScores.keySet()) {
                // NOTE: This metrics calc code duplicated from BenchmarkScore.calculateMetrics()
                // Calculate the metrics for this category
                TP_FN_TN_FP_Counts c = this.categoryGroupScores.get(categoryGroupLongname);
                int rowTotal = c.tp + c.fn + c.tn + c.fp;
                double precision = (double) c.tp / (double) (c.tp + c.fp);
                // c.tp & c.fp can both be zero, creating a precision of NaN. So set to 0.0.
                if (Double.isNaN(precision)) precision = 0.0;
                double tpr = (double) c.tp / (double) (c.tp + c.fn);
                double fpr = (double) c.fp / (double) (c.fp + c.tn);
                // c.fp & c.tn can both be zero, creating an fpr of NaN. So set to 0.0.
                if (Double.isNaN(fpr)) fpr = 0.0;

                // Add the metrics for this particular category. This put() doesn't automatically
                // update the tool's overall metrics, so those are calculated after this loop
                // completes.
                CategoryMetrics categoryMetrics =
                        new CategoryMetrics(categoryGroupLongname, precision, tpr, fpr, rowTotal);
                this.categoryGroupMetrics.put(categoryGroupLongname, categoryMetrics);

                // Add the metrics for this particular CategoryGroup. This add() doesn't
                // automatically update the tool's overall metrics, so those are calculated after
                // this loop completes.
                this.overallCategoryGroupMetrics.addCategoryMetrics(
                        categoryGroupLongname, precision, tpr, fpr, rowTotal);

                // Update the tool-wide totals per category
                totalFPRate += fpr;
                totalTPRate += tpr;
                // Note: The following 5 totals are identical to the vuln category totals
                total += rowTotal;
                totalTP += c.tp;
                totalFP += c.fp;
                totalFN += c.fn;
                totalTN += c.tn;
            }
            // Now Calculate and set metrics across all Category Groups
            int numCategoryGroups = this.categoryGroupScores.size();
            double totalPrecision = (double) totalTP / (double) (totalTP + totalFP);
            // tp & fp can both be zero, creating a precision of NaN. If so, set to 0.0.
            if (Double.isNaN(totalPrecision)) totalPrecision = 0.0;
            this.overallCategoryGroupMetrics.setPrecision(totalPrecision);
            this.overallCategoryGroupMetrics.setFalsePositiveRate(totalFPRate / numCategoryGroups);
            this.overallCategoryGroupMetrics.setTruePositiveRate(totalTPRate / numCategoryGroups);
            this.overallCategoryGroupMetrics.setTotalTestCases(total);
            this.overallCategoryGroupMetrics.setOverallFindingCounts(
                    totalTP, totalFP, totalFN, totalTN);
            // Copy over the scan time, if set
            this.overallCategoryGroupMetrics.setScanTime(toolVulnMetrics.getScanTime());
        } else {
            this.categoryGroupScores = null;
            this.categoryGroupMetrics = null;
            this.overallCategoryGroupMetrics = null;
        }
        this.actualResults = actualResults;
        this.overallVulnMetrics = toolVulnMetrics;
        this.actualResultsFileName = actualCSVResultsFileName;
    }

    /**
     * Gets the name of this tool.
     *
     * @return Name of the tool.
     */
    public String getToolName() {
        return this.toolName;
    }

    public String getToolNameAndVersion() {
        return this.toolNameAndVersion;
    }

    public boolean isCommercial() {
        return this.isCommercial;
    }

    public ToolType getToolType() {
        return toolType;
    }

    public String getTestSuiteVersion() {
        return this.testSuiteVersion;
    }

    public String getActualResultsFileName() {
        return actualResultsFileName;
    }

    /**
     * Gets the actual un-scored results for this tool.
     *
     * @return the actual results for this tool.
     */
    public TestSuiteResults getActualResults() {
        return this.actualResults;
    }

    /**
     * Gets all the scored metrics for all vulnerability categories for this tool.
     *
     * @return the requested tool metrics.
     */
    public ToolMetrics getOverallMetrics() {
        return this.overallVulnMetrics;
    }

    /**
     * Gets all the scored metrics for the specified category type for this tool.
     *
     * @param useCategoryGroups True if getting overall metrics for Category Groups, false for
     *     normal vulnerability categories
     * @return the requested tool metrics.
     */
    public ToolMetrics getOverallMetrics(boolean useCategoryGroups) {
        if (useCategoryGroups) return getOverallCategoryGroupMetrics();
        else return this.overallVulnMetrics;
    }

    /**
     * Get the metrics for this tool for all Category Groups. Fatal if CategoryGroups not enabled.
     *
     * @return A collection of the metrics per Category Group.
     */
    public Collection<CategoryMetrics> getCategoryGroupMetrics() {
        if (this.categoryGroupMetrics == null) {
            new Exception(
                            "FATAL INTERNAL ERROR: getCategoryGroupMetrics() called when CategoryGroups not enabled")
                    .printStackTrace();
            System.exit(-1);
        }
        return this.categoryGroupMetrics.values();
    }

    /**
     * Get the metrics for this tool for the specified CategoryGroup. Fatal if CategoryGroups not
     * enabled.
     *
     * @return The metrics for the specified category group.
     */
    private CategoryMetrics getCategoryGroupMetrics(String category) {
        if (this.categoryGroupMetrics == null) {
            new Exception(
                            "FATAL INTERNAL ERROR: getCategoryGroupMetrics() called when CategoryGroups not enabled")
                    .printStackTrace();
            System.exit(-1);
        }
        return this.categoryGroupMetrics.get(category);
    }

    /**
     * Get the metrics for this tool for all CategoryGroups. Fatal if CategoryGroups not enabled.
     *
     * @return A collection of the metrics per CategoryGroup.
     */
    public Set<String> getCategoryGroups() {
        if (this.categoryGroupMetrics == null) {
            new Exception(
                            "FATAL INTERNAL ERROR: getCategoryGroups() called when CategoryGroups not enabled")
                    .printStackTrace();
            System.exit(-1);
        }
        return this.categoryGroupMetrics.keySet();
    }

    /**
     * Get the metrics for this tool for this vulnerability category.
     *
     * @param category The category to get the metrics for.
     * @return Metrics for this vulnerability category.
     */
    private CategoryMetrics getCategoryMetrics(String category) {
        return this.overallVulnMetrics.getCategoryMetrics(category);
    }

    /**
     * Get the metrics for this tool for the specified category. If useCategoryGroups is true, this
     * returns the metrics for the specified Category Group. If false, returns the metrics for the
     * specified vulnerability category.
     *
     * @param category The category to get the metrics for.
     * @param useCategoryGroups True if getting metrics for CategoryGroups, false for normal
     *     vulnerability categories
     * @return Metrics for this vulnerability or Category Group category.
     */
    public CategoryMetrics getCategoryMetrics(String category, boolean useCategoryGroups) {
        if (useCategoryGroups) return getCategoryGroupMetrics(category);
        else return this.getCategoryMetrics(category);
    }

    /**
     * Gets the scored metrics for all the category groups for this tool.
     *
     * @return the scored metrics for all the category groups for this tool.
     */
    private ToolMetrics getOverallCategoryGroupMetrics() {
        if (this.overallCategoryGroupMetrics == null) {
            new Exception(
                            "FATAL INTERNAL ERROR: getOverallCategoryGroupMetrics() called when CategoryGroups not enabled")
                    .printStackTrace();
            System.exit(-1);
        }
        return this.overallCategoryGroupMetrics;
    }

    /**
     * Get the TP_FN_TN_FP_Counts for all vulnerability categories.
     *
     * @param forCategoryGroups True if getting category scores for CategoryGroups, false for normal
     *     vulnerability categories
     * @return A map of all the requested categories and the TP_FN_TN_FP_Counts for each category.
     */
    public Map<String, TP_FN_TN_FP_Counts> getCategoryScores(boolean forCategoryGroups) {
        if (forCategoryGroups) return this.categoryGroupScores;
        else return this.categoryScores;
    }

    /**
     * Compares the name and version of this tool, to the name and version of the supplied tool.
     * Used to sort Tools by tool name and version.
     */
    @Override
    public int compareTo(Tool r) {
        return this.getToolNameAndVersion()
                .toLowerCase()
                .compareTo(r.getToolNameAndVersion().toLowerCase());
    }
}
