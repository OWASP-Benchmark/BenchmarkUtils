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
 * @author Seqra Team
 * @created 2026
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

public class SeqraReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Seqra.sarif");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlySeqraReaderTestReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, SeqraReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        SeqraReader reader = new SeqraReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertEquals("Seqra", result.getToolName());
        assertEquals("v2.2.0", result.getToolVersion());
        assertFalse(result.isCommercial());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.WEAK_HASH_ALGO, result.get(2670).get(0).getCWE());
        assertEquals(CweNumber.INSECURE_COOKIE, result.get(2710).get(0).getCWE());
    }

    @Test
    void mapCweMapsInsecureCookieCwe() {
        SeqraReader reader = new SeqraReader();

        // CWE-319 (Cleartext Transmission) should map to CWE-614 (Insecure Cookie)
        assertEquals(CweNumber.INSECURE_COOKIE, reader.mapCwe(319));

        // Other CWEs should pass through unchanged
        assertEquals(328, reader.mapCwe(328));
        assertEquals(327, reader.mapCwe(327));
    }
}
