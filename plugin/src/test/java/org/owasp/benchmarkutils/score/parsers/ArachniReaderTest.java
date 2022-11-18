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

public class ArachniReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Arachni-v2.0dev.xml");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyArachniReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, ArachniReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        ArachniReader reader = new ArachniReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.DAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("Arachni", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.XSS, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());
    }
}
