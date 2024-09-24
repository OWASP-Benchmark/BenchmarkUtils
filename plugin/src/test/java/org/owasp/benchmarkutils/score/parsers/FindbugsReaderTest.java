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
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class FindbugsReaderTest extends ReaderTestBase {

    private static ResultFile findSecBugsResultFile;
    private static ResultFile spotBugsResultFile;

    @BeforeAll
    static void setUp() {
        findSecBugsResultFile =
                TestHelper.resultFileOf("testfiles/Benchmark_findsecbugs-v1.11.0-105.xml");
        spotBugsResultFile = TestHelper.resultFileOf("testfiles/Benchmark_spotbugs-v4.1.4-104.xml");
    }

    @Test
    public void onlyFindbugsReaderReportsCanReadAsTrueForFindSecBugsFile() {
        assertOnlyMatcherClassIs(findSecBugsResultFile, FindbugsReader.class);
    }

    @Test
    public void onlyFindbugsReaderReportsCanReadAsTrueForSpotBugsFile() {
        assertOnlyMatcherClassIs(spotBugsResultFile, FindbugsReader.class);
    }

    @Test
    void readerHandlesGivenFindSecBugsResultFile() throws Exception {
        FindbugsReader reader = new FindbugsReader();
        TestSuiteResults result = reader.parse(findSecBugsResultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("SBwFindSecBugs", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.XSS, result.getTestCaseResults("1").get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.getTestCaseResults("2").get(0).getCWE());
    }

    @Test
    void readerHandlesGivenSpotBugsResultFile() throws Exception {
        FindbugsReader reader = new FindbugsReader();
        TestSuiteResults result = reader.parse(spotBugsResultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("SpotBugs", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.SQL_INJECTION, result.getTestCaseResults("1").get(0).getCWE());
        assertEquals(
                23,
                result.getTestCaseResults("2").get(0).getCWE()); // 23 is Relative Path Traversal
    }
}
