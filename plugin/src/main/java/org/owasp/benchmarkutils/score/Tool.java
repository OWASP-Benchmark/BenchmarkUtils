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

import java.util.Map;
import org.owasp.benchmarkutils.score.TestSuiteResults.ToolType;

public class Tool implements Comparable<Tool> {

    /*
     * This class contains all the details for a specific tool, including all the results scored for the tool.
     * A side effect of creating an instance of Tool is that the HTML report for this tool, and the .csv actual results files
     * are both created to support scorecard generation.
     */

    private final boolean isCommercial;
    private final ToolType toolType;
    private String toolName = "not specified";
    private final String toolNameAndVersion;
    private final String testSuiteVersion;
    private final Map<String, TP_FN_TN_FP_Counts> scores; // This tool's scores per category.
    private final TestSuiteResults actualResults;
    private final ToolResults overallResults; // The scored results for this tool.
    private final String actualResultsFileName; // Name of this tool's .csv computed results file

    public Tool(
            TestSuiteResults actualResults,
            Map<String, TP_FN_TN_FP_Counts> scores,
            ToolResults toolResults,
            String actualCSVResultsFileName,
            boolean isCommercial) {

        this.isCommercial = isCommercial;
        this.toolType = actualResults.toolType;
        this.toolName = actualResults.getToolName();
        this.toolNameAndVersion = actualResults.getToolNameAndVersion();
        this.testSuiteVersion = actualResults.getTestSuiteVersion();

        this.scores = scores;
        this.actualResults = actualResults;
        this.overallResults = toolResults;
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
     * Gets the actual unscored results for this tool.
     *
     * @return the actual results for this tool.
     */
    public TestSuiteResults getActualResults() {
        return this.actualResults;
    }

    /**
     * Gets the scored results for this tool.
     *
     * @return the overall results for this tool.
     */
    public ToolResults getOverallResults() {
        return this.overallResults;
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

    public Map<String, TP_FN_TN_FP_Counts> getScores() {
        return this.scores;
    }
}
