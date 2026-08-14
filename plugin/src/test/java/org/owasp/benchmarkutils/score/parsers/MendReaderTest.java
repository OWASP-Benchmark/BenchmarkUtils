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
 * @author Sascha Knoop, Jan Kühl
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class MendReaderTest extends ReaderTestBase {

    private ResultFile resultFileLegacy;
    private ResultFile resultFile2023;

    @BeforeEach
    void setUp() {
        resultFileLegacy = TestHelper.resultFileOf("testfiles/Benchmark_Mend.xml");
        resultFile2023 = TestHelper.resultFileOf("testfiles/Benchmark_Mend_2023.xml");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyMendReaderReportsCanReadAsTrueForLegacyFormat() {
        assertOnlyMatcherClassIs(this.resultFileLegacy, MendReader.class);
    }

    @Test
    public void onlyMendReaderReportsCanReadAsTrueForFormat2023() {
        assertOnlyMatcherClassIs(this.resultFile2023, MendReader.class);
    }

    @Test
    void readerHandlesLegacyReportFormat() throws Exception {
        MendReader reader = new MendReader();
        TestSuiteResults result = reader.parse(resultFileLegacy);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Mend SAST", result.getToolName());
        assertEquals("01:23:45", result.getTime());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.SQL_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.COMMAND_INJECTION, result.get(2).get(0).getCWE());
    }

    @Test
    void readerHandlesReportFormat2023() throws Exception {
        MendReader reader = new MendReader();
        TestSuiteResults result = reader.parse(resultFile2023);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Mend SAST", result.getToolName());
        assertEquals("01:23:45", result.getTime());

        assertEquals(3, result.getTotalResults());

        assertEquals(CweNumber.SQL_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.COMMAND_INJECTION, result.get(2).get(0).getCWE());
        assertEquals(CweNumber.WEAK_RANDOM, result.get(3).get(0).getCWE());
    }
}
