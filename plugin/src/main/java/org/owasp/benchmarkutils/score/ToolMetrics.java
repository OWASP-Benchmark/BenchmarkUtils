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
package org.owasp.benchmarkutils.score;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * This class holds all the metrics per category for a tool's scan of a test suite. It contains
 * CategoryMetrics for each vulnerability category or CategoryGroup in the test suite. It also
 * contains some overall results data like the overall score, and the true positive and false
 * positive rates.
 */
public class ToolMetrics {

    // A map of each category name to the overall metrics for that vuln category or CategoryGroup
    // for a specific tool.
    private Map<String, CategoryMetrics> categoryMetricsMap =
            new TreeMap<String, CategoryMetrics>();
    private double overallScore =
            0; // The overall score for this tool. Autocalculated when TPR or FPR changed.
    private int total =
            0; // The total number of TP, FP, FN, TN across all test cases for this tool.

    // The overall rates for this tool. These are values between 1 and 0.
    private double precision = 0; // TP / (TP + FP)
    private double TPRate = 0; // TPR is also Recall (TP / (TP + FN))
    private double FPRate = 0;
    private double FScore =
            0; // 2 * precision * TPR / (Precision + TPR). Auto updated when values changed.

    private TP_FN_TN_FP_Counts findingCounts;

    // If set, scan time in human readable form (e.g., 0:4:25, meaning 4 minutes, 25 seconds)
    private String scanTime = "Unknown";

    /**
     * Add the overall metrics for a specific category to these ToolMetrics. This is only for
     * precision, T/F PRs, and the total, not the finding counts for TPs, FNs, TNs, and FPs. Note
     * that this add() does not automatically update any of the overall results for this tool. You
     * must do that yourself via the setters for this class.
     *
     * @param category - The vuln category.
     * @param precision - Precision score in this category.
     * @param tpr - True Positive Rate in this category.
     * @param fpr - False Positive Rate in this category.
     * @param total - Total number of results in this category.
     */
    public void addCategoryMetrics(
            String category, double precision, double tpr, double fpr, int total) {
        CategoryMetrics r = new CategoryMetrics(category, precision, tpr, fpr, total);
        categoryMetricsMap.put(category, r);
    }

    /**
     * Get the overall metrics for a particular vulnerability category.
     *
     * @param category
     * @return The metrics for the specified vulnerability category. Null if the category isn't
     *     found.
     */
    public CategoryMetrics getCategoryMetrics(String category) {
        return this.categoryMetricsMap.get(category);
    }

    /**
     * Get the overall metrics for this tool for all vulnerability categories.
     *
     * @return A collection of metrics per vuln category.
     */
    public Collection<CategoryMetrics> getCategoryMetrics() {
        return this.categoryMetricsMap.values();
    }

    /**
     * Get all the vuln categories that have metrics calculated.
     *
     * @return The collection of category IDs.
     */
    public Set<String> getCategories() {
        return this.categoryMetricsMap.keySet();
    }

    /**
     * Returns the overall score for this tool. This is the True Positive Rate - the False Positive
     * rate.
     *
     * @return This tool's overall score.
     */
    public double getOverallScore() {
        return this.overallScore;
    }

    /**
     * Returns the overall F-score for this tool. Calculated as: 2 * precision * TPR / (Precision +
     * TPR)
     *
     * @return This tool's overall F-score.
     */
    public double getFScore() {
        return this.FScore;
    }

    /**
     * Returns the overall true positive rate for this tool.
     *
     * @return This tool's true positive rate.
     */
    public double getPrecision() {
        return this.precision;
    }

    /** Sets the overall precision for this tool, and updates F-score. */
    public void setPrecision(double precision) {
        // Update the F-score since it depends on precision and TPR.
        double fscore = 2 * precision * this.TPRate / (precision + this.TPRate);
        if (Double.isNaN(fscore)) {
            this.FScore = 0.0;
        } else this.FScore = fscore;
        this.precision = precision;
    }

    /**
     * Returns the overall true positive rate for this tool.
     *
     * @return This tool's true positive rate.
     */
    public double getTruePositiveRate() {
        return this.TPRate;
    }

    /**
     * Sets the overall true positive rate for this tool, updates F-score, and updates overall
     * score.
     *
     * @param rate The true positive rate
     */
    public void setTruePositiveRate(double rate) {
        // Update the F-score since it depends on precision and TPR.
        double fscore = 2 * this.precision * rate / (this.precision + rate);
        if (Double.isNaN(fscore)) {
            this.FScore = 0.0;
        } else this.FScore = fscore;
        this.TPRate = rate;

        // Also update score
        this.overallScore = rate - this.FPRate;
    }

    /**
     * Returns the false positive rate for this tool.
     *
     * @return This tool's true positive rate.
     */
    public double getFalsePositiveRate() {
        return this.FPRate;
    }

    /**
     * Sets the false positive rate for this tool, and updates overall score.
     *
     * @param rate The false positive rate
     */
    public void setFalsePositiveRate(double rate) {
        this.FPRate = rate;
        // Also update score
        this.overallScore = this.TPRate - rate;
    }

    /**
     * Returns the total number of test cases processed with this tool.
     *
     * @return The total.
     */
    public int getTotalTestCases() {
        return this.total;
    }

    /**
     * Set the total number of test cases processed with this tool.
     *
     * @param The total.
     */
    public void setTotalTestCases(int total) {
        this.total = total;
    }

    /**
     * Returns the amount of time it took to run a scan of the Test Suite with this tool.
     *
     * @return The scan time, in human readable form (e.g., 0:4:25, meaning 4 minutes, 25 seconds)
     */
    public String getScanTime() {
        return this.scanTime;
    }

    /**
     * Set the amount of time it took to run a scan of the Test Suite with this tool.
     *
     * @param The scan time, in human readable form (e.g., 0:4:25, meaning 4 minutes, 25 seconds).
     */
    public void setScanTime(String scanTime) {
        this.scanTime = scanTime;
    }

    /**
     * Set the overall finding counts for this tool across all the test cases.
     *
     * @param tp Number of true positives (good)
     * @param fp Number of false positives (bad)
     * @param fn Number of false negatives (bad)
     * @param tn Number of true negatives (good)
     */
    public void setOverallFindingCounts(int tp, int fp, int fn, int tn) {
        this.findingCounts = new TP_FN_TN_FP_Counts();
        this.findingCounts.tp = tp;
        this.findingCounts.fp = fp;
        this.findingCounts.fn = fn;
        this.findingCounts.tn = tn;
    }

    /**
     * Get the overall finding counts for this tool across all the test cases.
     *
     * @return The findings counts
     */
    public TP_FN_TN_FP_Counts getOverallFindingCounts() {
        return this.findingCounts;
    }
}
