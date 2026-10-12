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
 * @author Cyril Yepifanov
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.parsers.ReaderTestBase;

class PVSStudioReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_PVS-Studio-7.42.sarif");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    void onlyPVSStudioReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, PVSStudioReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        PVSStudioReader reader = new PVSStudioReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertEquals("PVS-Studio", result.getToolName());
        assertEquals("7.42.105218.307", result.getToolVersion());
        assertTrue(result.isCommercial());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.LDAP_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.WEAK_CRYPTO_ALGO, result.get(2).get(0).getCWE());
    }
}
