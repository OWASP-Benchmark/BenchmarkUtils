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
 * @author Julien Delange
 * @created 2024
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.parsers.ReaderTestBase;

public class DatadogSastReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_DatadogSast.sarif");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void canReadFile() {
        assertOnlyMatcherClassIs(this.resultFile, DatadogSastReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        DatadogSastReader reader = new DatadogSastReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertEquals("DatadogSast", result.getToolName());
        assertEquals("0.2.9", result.getToolVersion());
        assertFalse(result.isCommercial());

        assertEquals(1, result.getTotalResults());

        assertEquals(CweNumber.INSECURE_COOKIE, result.get(10).get(0).getCWE());
    }
}
