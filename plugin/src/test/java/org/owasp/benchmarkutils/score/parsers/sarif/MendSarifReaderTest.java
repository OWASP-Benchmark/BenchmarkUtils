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
 * @author Jan Kühl
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.*;
import org.owasp.benchmarkutils.score.parsers.ReaderTestBase;

public class MendSarifReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Mend.sarif");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyMendSarifReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, MendSarifReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        MendSarifReader reader = new MendSarifReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Mend SAST", result.getToolName());
        assertEquals("26.6.1.2", result.getToolVersion());

        assertEquals(3, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.get(2).get(0).getCWE());
        assertEquals(CweNumber.WEAK_RANDOM, result.get(3).get(0).getCWE());
    }
}
