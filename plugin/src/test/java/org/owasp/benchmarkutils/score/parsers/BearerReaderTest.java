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
 * @author Cédric Fabianski
 * @created 2023
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

public class BearerReaderTest extends ReaderTestBase {

    private ResultFile resultFileV1_30;

    @BeforeEach
    void setUp() {
        resultFileV1_30 = TestHelper.resultFileOf("testfiles/Benchmark_Bearer-v1.30.0.jsonv2");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyBearerReaderReportsCanReadAsTrueForV1_30() {
        assertOnlyMatcherClassIs(this.resultFileV1_30, BearerReader.class);
    }

    @Test
    void readerHandlesGivenResultFileInV1_30() throws Exception {
        BearerReader reader = new BearerReader();
        TestSuiteResults result = reader.parse(resultFileV1_30);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("Bearer", result.getToolName());
        assertEquals("v1.30.0", result.getToolVersion());

        assertEquals(3, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(7).get(0).getCWE());
        assertEquals(CweNumber.WEAK_HASH_ALGO, result.get(5).get(0).getCWE());
        assertEquals(CweNumber.WEAK_CRYPTO_ALGO, result.get(35).get(0).getCWE());
    }
}
