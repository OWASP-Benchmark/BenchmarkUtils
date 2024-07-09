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
import static org.owasp.benchmarkutils.score.report.Formats.singleDecimalPlaceNumber;

import java.util.ArrayList;
import java.util.List;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;
import org.owasp.benchmarkutils.score.report.ScatterVulns;

public class CommercialAveragesTable {

    private final List<ScatterVulns> entries = new ArrayList<>();
    private final TestSuiteName testSuiteName;
    private final String testSuiteVersion;

    public CommercialAveragesTable(TestSuiteName testSuiteName, String testSuiteVersion) {
        this.testSuiteName = testSuiteName;
        this.testSuiteVersion = testSuiteVersion;
    }

    public void add(ScatterVulns scatter) {
        entries.add(scatter);
    }

    public String render() {
        HtmlStringBuilder htmlBuilder = new HtmlStringBuilder();

        htmlBuilder.beginTable("table");

        addHeaderTo(htmlBuilder);

        entries.forEach(scatter -> appendRowTo(htmlBuilder, scatter));

        addFooterTo(htmlBuilder);

        htmlBuilder.endTable();

        return htmlBuilder.toString();
    }

    private int commercialToolTotal() {
        return entries.get(0).getCommercialToolCount();
    }

    private void addHeaderTo(HtmlStringBuilder htmlBuilder) {
        htmlBuilder.beginTr();
        htmlBuilder.th("Vulnerability Category");
        htmlBuilder.th("Low Tool Type");
        htmlBuilder.th("Low Score");
        htmlBuilder.th("Ave Score");
        htmlBuilder.th("High Score");
        htmlBuilder.th("High Tool Type");
        htmlBuilder.endTr();
    }

    private void appendRowTo(HtmlStringBuilder htmlBuilder, ScatterVulns scatter) {
        htmlBuilder.beginTr();
        htmlBuilder.td(scatter.CATEGORY);
        htmlBuilder.td(scatter.getCommercialLowToolType() + "");

        htmlBuilder.td(scatter.getCommercialLow(), cssClassFor(scatter.getCommercialLow()));
        htmlBuilder.td(scatter.getCommercialAve());

        htmlBuilder.td(scatter.getCommercialHigh(), cssClassFor(scatter.getCommercialHigh()));
        htmlBuilder.td(scatter.getCommercialHighToolType() + "");
        htmlBuilder.endTr();
    }

    private static String cssClassFor(int commercialLow) {
        String cssClass = null;

        if (commercialLow <= 10) {
            cssClass = "danger";
        } else if (commercialLow >= 50) {
            cssClass = "success";
        }

        return cssClass;
    }

    private void addFooterTo(HtmlStringBuilder htmlBuilder) {
        htmlBuilder.beginTr();
        htmlBuilder.td("Average across all categories for " + commercialToolTotal() + " tools");
        htmlBuilder.td("");
        htmlBuilder.td(
                singleDecimalPlaceNumber.format(
                        (float) commercialLowTotal() / (float) entries.size()));
        htmlBuilder.td(
                singleDecimalPlaceNumber.format(
                        (float) commercialAveTotal() / (float) entries.size()));
        htmlBuilder.td(
                singleDecimalPlaceNumber.format(
                        (float) commercialHighTotal() / (float) entries.size()));
        htmlBuilder.td("");
        htmlBuilder.endTr();
    }

    // formattedRatio

    private int commercialHighTotal() {
        return entries.stream().mapToInt(ScatterVulns::getCommercialHigh).sum();
    }

    private int commercialAveTotal() {
        return entries.stream().mapToInt(ScatterVulns::getCommercialAve).sum();
    }

    private int commercialLowTotal() {
        return entries.stream().mapToInt(ScatterVulns::getCommercialLow).sum();
    }

    public boolean hasEntries() {
        return !entries.isEmpty();
    }

    public String filename() {
        return format(
                "{0}_v{1}_Scorecard_for_Commercial_Tools.html",
                testSuiteName.simpleName(), testSuiteVersion);
    }
}
