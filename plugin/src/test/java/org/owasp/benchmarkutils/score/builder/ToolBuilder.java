package org.owasp.benchmarkutils.score.builder;

import java.util.HashMap;
import java.util.Map;
import org.owasp.benchmarkutils.score.TP_FN_TN_FP_Counts;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.Tool;
import org.owasp.benchmarkutils.score.ToolResults;

public class ToolBuilder {

    private TestSuiteResults testSuiteResults = TestSuiteResultsBuilder.builder().build();
    private Map<String, TP_FN_TN_FP_Counts> scores = new HashMap<>();
    private ToolResults toolResults = new ToolResults();
    private String actualCsvResultFileName = "";
    private boolean isCommercial = false;

    private ToolBuilder() {}

    public static ToolBuilder builder() {
        return new ToolBuilder();
    }

    public ToolBuilder setTestSuiteResults(TestSuiteResults testSuiteResults) {
        this.testSuiteResults = testSuiteResults;

        return this;
    }

    public ToolBuilder setScores(Map<String, TP_FN_TN_FP_Counts> scores) {
        this.scores = scores;

        return this;
    }

    public ToolBuilder setScore(String key, TP_FN_TN_FP_Counts value) {
        this.scores.put(key, value);

        return this;
    }

    public ToolBuilder setToolResults(ToolResults toolResults) {
        this.toolResults = toolResults;

        return this;
    }

    public ToolBuilder setActualCsvResultFileName(String actualCsvResultFileName) {
        this.actualCsvResultFileName = actualCsvResultFileName;

        return this;
    }

    public ToolBuilder setIsCommercial(boolean isCommercial) {
        this.isCommercial = isCommercial;

        return this;
    }

    public Tool build() {
        return new Tool(
                testSuiteResults, scores, toolResults, actualCsvResultFileName, isCommercial);
    }
}
