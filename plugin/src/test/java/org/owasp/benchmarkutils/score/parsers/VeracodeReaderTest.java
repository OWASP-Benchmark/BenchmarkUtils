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
 * @author Barath Raj
 * @created 2023
 */
package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

class VeracodeReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Veracode.xml");
    }

    @Test
    void onlyVeracodeReportCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, VeracodeReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        VeracodeReader reader = new VeracodeReader();
        TestSuiteResults result = reader.parse(this.resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Veracode SAST", result.getToolName());

        assertEquals(3, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.getTestCaseResults("7").get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.getTestCaseResults("8").get(0).getCWE());
    }
}
