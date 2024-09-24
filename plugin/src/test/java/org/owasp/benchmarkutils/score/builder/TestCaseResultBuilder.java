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
package org.owasp.benchmarkutils.score.builder;

import org.owasp.benchmarkutils.score.CweMatchDetails;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.TestCaseResult;

public class TestCaseResultBuilder {

    private String testCaseName = "SomeTest";
    private int testNumber = -1;
    private int cwe = CweNumber.DONTCARE;
    private boolean truePositive = false;
    private boolean passed = false;

    private String source = null;
    private String dataFlow = null;
    private String sink = null;

    // Have to set CweMatch details for actual results, or you get a null pointer
    // The actual values usually don't matter for these tests, so we create a default
    private CweMatchDetails cweMatchDetails = new CweMatchDetails(1, true, true, -1, "");

    private TestCaseResultBuilder() {}

    public static TestCaseResultBuilder builder() {
        return new TestCaseResultBuilder();
    }

    public TestCaseResultBuilder setTestCaseName(String testCaseName) {
        this.testCaseName = testCaseName;

        return this;
    }

    public TestCaseResultBuilder setTestNumber(int testNumber) {
        this.testNumber = testNumber;

        return this;
    }

    public TestCaseResultBuilder setCwe(int cwe) {
        this.cwe = cwe;

        return this;
    }

    public TestCaseResultBuilder setSource(String source) {
        this.source = source;

        return this;
    }

    public TestCaseResultBuilder setDataFlow(String dataFlow) {
        this.dataFlow = dataFlow;

        return this;
    }

    public TestCaseResultBuilder setSink(String sink) {
        this.sink = sink;

        return this;
    }

    public TestCaseResultBuilder setTruePositive(boolean truePositive) {
        this.truePositive = truePositive;

        return this;
    }

    public TestCaseResultBuilder setPassed(boolean passed) {
        this.passed = passed;

        return this;
    }

    public TestCaseResult build() {
        TestCaseResult testCaseResult = new TestCaseResult();

        testCaseResult.setTestCaseName(testCaseName);
        testCaseResult.setTestID(testNumber);
        testCaseResult.setCWE(cwe);
        testCaseResult.setSource(source);
        testCaseResult.setDataFlow(dataFlow);
        testCaseResult.setSink(sink);
        testCaseResult.setTruePositive(truePositive);
        testCaseResult.addMatchDetails(cweMatchDetails);
        testCaseResult.setPassed(passed);

        return testCaseResult;
    }
}
