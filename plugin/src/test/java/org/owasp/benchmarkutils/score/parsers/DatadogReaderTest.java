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
 * @author Ander Ruiz
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class DatadogReaderTest extends ReaderTestBase {

    private static ResultFile resultFile;

    @BeforeAll
    static void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_1.2-Datadog.log");
    }

    @Test
    public void onlyDatadogReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(resultFile, DatadogReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        DatadogReader reader = new DatadogReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.IAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Datadog", result.getToolName());
        assertEquals("0.108.0", result.getToolVersion());

        assertEquals(4, result.getTotalResults());

        assertEquals(
                CweNumber.COMMAND_INJECTION, result.getTestCaseResults("1609").get(0).getCWE());
        assertEquals(CweNumber.PATH_TRAVERSAL, result.getTestCaseResults("2").get(0).getCWE());
        assertEquals(CweNumber.WEAK_HASH_ALGO, result.getTestCaseResults("1").get(0).getCWE());
        assertEquals(
                CweNumber.TRUST_BOUNDARY_VIOLATION, result.getTestCaseResults("4").get(0).getCWE());
    }
}
