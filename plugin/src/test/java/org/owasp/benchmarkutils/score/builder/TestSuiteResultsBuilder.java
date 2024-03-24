package org.owasp.benchmarkutils.score.builder;

import org.owasp.benchmarkutils.score.TestSuiteResults;

public class TestSuiteResultsBuilder {

    private String toolname = "";
    private boolean isCommercial = false;
    private TestSuiteResults.ToolType toolType = TestSuiteResults.ToolType.SAST;

    private TestSuiteResultsBuilder() {}

    public static TestSuiteResultsBuilder builder() {
        return new TestSuiteResultsBuilder();
    }

    public TestSuiteResultsBuilder setToolname(String toolname) {
        this.toolname = toolname;

        return this;
    }

    public TestSuiteResultsBuilder setIsCommercial(boolean isCommercial) {
        this.isCommercial = isCommercial;

        return this;
    }

    public TestSuiteResultsBuilder setToolType(TestSuiteResults.ToolType toolType) {
        this.toolType = toolType;

        return this;
    }

    public TestSuiteResults build() {
        return new TestSuiteResults(toolname, isCommercial, toolType);
    }
}
