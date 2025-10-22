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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Sascha Knoop
 * @created 2024
 */
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
