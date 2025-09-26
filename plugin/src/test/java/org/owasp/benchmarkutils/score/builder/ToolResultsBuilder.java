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
import org.owasp.benchmarkutils.score.CategoryResults;
import org.owasp.benchmarkutils.score.ToolResults;

public class ToolResultsBuilder {

    private Set<CategoryResults> categoryResults = new HashSet<>();
    private double truePositiveRate = 0;
    private double falsePositiveRate = 0;
    private double precision = 0;

    private ToolResultsBuilder() {}

    public static ToolResultsBuilder builder() {
        return new ToolResultsBuilder();
    }

    public ToolResults build() {
        ToolResults results = new ToolResults();

        results.setTruePositiveRate(truePositiveRate);
        results.setFalsePositiveRate(falsePositiveRate);
        results.setPrecision(precision);

        categoryResults.forEach(
                cr ->
                        results.add(
                                cr.category,
                                cr.precision,
                                cr.truePositiveRate,
                                cr.falsePositiveRate,
                                cr.totalTestCases));

        return results;
    }

    public ToolResultsBuilder setCategoryResults(Set<CategoryResults> categoryResultsMap) {
        this.categoryResults = categoryResultsMap;

        return this;
    }

    public ToolResultsBuilder addCategoryResult(CategoryResults result) {
        this.categoryResults.add(result);

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
