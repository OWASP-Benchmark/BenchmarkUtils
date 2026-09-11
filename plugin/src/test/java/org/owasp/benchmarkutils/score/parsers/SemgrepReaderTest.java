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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SemgrepReaderTest extends ReaderTestBase {

    private ResultFile resultFileV65;
    private ResultFile resultFileV121;

    @BeforeEach
    void setUp() {
        resultFileV65 = TestHelper.resultFileOf("testfiles/Benchmark_semgrep-v0.65.0.json");
        resultFileV121 =
                TestHelper.resultFileWithoutLineBreaksOf(
                        "testfiles/Benchmark_semgrep-v0.121.0.json");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlySemgrepReaderReportsCanReadAsTrueForV65() {
        assertOnlyMatcherClassIs(this.resultFileV65, SemgrepReader.class);
    }

    @Test
    public void onlySemgrepReaderReportsCanReadAsTrueForV121() {
        assertOnlyMatcherClassIs(this.resultFileV121, SemgrepReader.class);
    }

    @Test
    void readerHandlesGivenResultFileInV65() throws Exception {
        SemgrepReader reader = new SemgrepReader();
        TestSuiteResults result = reader.parse(resultFileV65);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("Semgrep", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.SQL_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.INSECURE_COOKIE, result.get(2).get(0).getCWE());
    }

    @Test
    void readerHandlesGivenResultFileInV121() throws Exception {
        SemgrepReader reader = new SemgrepReader();
        TestSuiteResults result = reader.parse(resultFileV121);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("Semgrep", result.getToolName());

        assertEquals(5, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(3).get(0).getCWE());
        assertEquals(CweNumber.COOKIE_WITHOUT_HTTPONLY, result.get(4).get(0).getCWE());
        assertEquals(CweNumber.COMMAND_INJECTION, result.get(5).get(0).getCWE());
        assertEquals(CweNumber.WEAK_CRYPTO_ALGO, result.get(6).get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.get(7).get(0).getCWE());
    }

    @Test
    void translateCwe77ReturnsCommandInjection() {
        assertEquals(
                CweNumber.COMMAND_INJECTION,
                SemgrepReader.translate(77),
                "CWE-77 (Command Injection parent) should map to 78 (COMMAND_INJECTION)");
    }

    @Test
    void translateCwe780ReturnsWeakCrypto() {
        assertEquals(
                CweNumber.WEAK_CRYPTO_ALGO,
                SemgrepReader.translate(780),
                "CWE-780 (RSA without OAEP) should map to 327 (WEAK_CRYPTO_ALGO)");
    }

    @Test
    void translateCwe943ReturnsSqlInjection() {
        assertEquals(
                CweNumber.SQL_INJECTION,
                SemgrepReader.translate(943),
                "CWE-943 (Data Query Injection) should map to 89 (SQL_INJECTION)");
    }

    @Test
    void translateDontCareCwesReturnAsIs() {
        assertEquals(75, SemgrepReader.translate(75), "CWE-75 should pass through unchanged");
        assertEquals(778, SemgrepReader.translate(778), "CWE-778 should pass through unchanged");
        assertEquals(942, SemgrepReader.translate(942), "CWE-942 should pass through unchanged");
        assertEquals(502, SemgrepReader.translate(502), "CWE-502 should pass through unchanged");
    }
}
