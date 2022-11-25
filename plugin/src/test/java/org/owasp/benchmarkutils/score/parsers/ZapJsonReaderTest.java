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

public class ZapJsonReaderTest extends ReaderTestBase {

    private ResultFile resultFileOldFormat;
    private ResultFile resultFileNewFormat;

    @BeforeEach
    void setUp() {
        resultFileOldFormat =
                TestHelper.resultFileOf("testfiles/Benchmark_ZAP-v2.10.0-oldfmt.json");
        resultFileNewFormat = TestHelper.resultFileOf("testfiles/Benchmark_ZAP-v2.11.1.json");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyZapJsonReaderReportsCanReadAsTrueForOldFormat() {
        assertOnlyMatcherClassIs(this.resultFileOldFormat, ZapJsonReader.class);
    }

    @Test
    public void onlyZapJsonReaderReportsCanReadAsTrueForNewFormat() {
        assertOnlyMatcherClassIs(this.resultFileNewFormat, ZapJsonReader.class);
    }

    @Test
    void readerHandlesGivenOldFormatResultFile() throws Exception {
        ZapJsonReader reader = new ZapJsonReader();
        TestSuiteResults result = reader.parse(resultFileOldFormat);

        assertEquals(TestSuiteResults.ToolType.DAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("OWASP ZAP", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.PATH_TRAVERSAL, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());
    }

    @Test
    void readerHandlesGivenNewFormatResultFile() throws Exception {
        ZapJsonReader reader = new ZapJsonReader();
        TestSuiteResults result = reader.parse(resultFileNewFormat);

        assertEquals(TestSuiteResults.ToolType.DAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("OWASP ZAP", result.getToolName());
        assertEquals("2.11.1", result.getToolVersion());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.CSRF, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.COOKIE_WITHOUT_HTTPONLY, result.get(2).get(0).getCWE());
    }
}
