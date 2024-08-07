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

class SemgrepSarifReaderTest extends ReaderTestBase {

    private ResultFile resultFileOSS, resultFilePRO;

    @BeforeEach
    void setUp() {
        resultFileOSS = TestHelper.resultFileOf("testfiles/Benchmark_semgrep-oss-v1.67.0.sarif");
        resultFilePRO = TestHelper.resultFileOf("testfiles/Benchmark_semgrep-pro-v1.68.1.sarif");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlySemgrepSarifReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFileOSS, SemgrepSarifReader.class);
        assertOnlyMatcherClassIs(this.resultFilePRO, SemgrepSarifReader.class);
    }

    @Test
    void readerHandlesSemgrepOSSResultFile() throws Exception {
        SemgrepSarifReader reader = new SemgrepSarifReader();
        TestSuiteResults result = reader.parse(resultFileOSS);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("Semgrep OSS", result.getToolName());
        assertEquals("1.67.0", result.getToolVersion());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.COOKIE_WITHOUT_HTTPONLY, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());
    }

    @Test
    void readerHandlesSemgrepPROResultFile() throws Exception {
        SemgrepSarifReader reader = new SemgrepSarifReader();
        TestSuiteResults result = reader.parse(resultFilePRO);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("Semgrep PRO", result.getToolName());
        assertEquals("1.68.1", result.getToolVersion());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.COOKIE_WITHOUT_HTTPONLY, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());
    }
}
