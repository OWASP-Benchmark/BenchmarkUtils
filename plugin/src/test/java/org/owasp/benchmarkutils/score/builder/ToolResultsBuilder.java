package org.owasp.benchmarkutils.score.builder;

import java.util.HashSet;
import java.util.Set;
import org.owasp.benchmarkutils.score.CategoryMetrics;
import org.owasp.benchmarkutils.score.ToolMetrics;

public class ToolResultsBuilder {

    private Set<CategoryMetrics> categoryMetrics = new HashSet<>();
    private double truePositiveRate = 0;
    private double falsePositiveRate = 0;
    private double precision = 0;

    private ToolResultsBuilder() {}

    public static ToolResultsBuilder builder() {
        return new ToolResultsBuilder();
    }

    public ToolMetrics build() {
        ToolMetrics results = new ToolMetrics();

        results.setTruePositiveRate(truePositiveRate);
        results.setFalsePositiveRate(falsePositiveRate);
        results.setPrecision(precision);

        categoryMetrics.forEach(
                cr ->
                        results.addCategoryMetrics(
                                cr.category,
                                cr.precision,
                                cr.truePositiveRate,
                                cr.falsePositiveRate,
                                cr.totalTestCases));

        return results;
    }

    public ToolResultsBuilder setCategoryMetrics(Set<CategoryMetrics> categoryMetricsMap) {
        this.categoryMetrics = categoryMetricsMap;

        return this;
    }

    public ToolResultsBuilder addCategoryResult(CategoryMetrics result) {
        this.categoryMetrics.add(result);

        return this;
    }

    public ToolResultsBuilder setTruePositiveRate(double truePositiveRate) {
        this.truePositiveRate = truePositiveRate;

        return this;
    }

    public ToolResultsBuilder setFalsePositiveRate(double falsePositiveRate) {
        this.falsePositiveRate = falsePositiveRate;

        return this;
    }

    public ToolResultsBuilder setPrecision(double precision) {
        this.precision = precision;

        return this;
    }
}
