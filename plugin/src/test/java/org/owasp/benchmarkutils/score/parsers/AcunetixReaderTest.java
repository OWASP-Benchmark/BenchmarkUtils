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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class AcunetixReaderTest extends ReaderTestBase {

    private ResultFile resultFile_360, resultFile_WVS;

    @BeforeEach
    void setUp() {
        resultFile_360 = TestHelper.resultFileOf("testfiles/Benchmark_Acunetix-v1.4.1.xml");
        resultFile_WVS = TestHelper.resultFileOf("testfiles/Benchmark_Acunetix-v15.3.xml");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyAcunetixReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile_360, AcunetixReader.class);
        assertOnlyMatcherClassIs(this.resultFile_WVS, AcunetixReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        // For Acunetix 360
        AcunetixReader reader = new AcunetixReader();
        TestSuiteResults result = reader.parse(resultFile_360);

        assertEquals(TestSuiteResults.ToolType.DAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Acunetix 360", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());

        // For Acunetix WVS
        reader = new AcunetixReader();
        result = reader.parse(resultFile_WVS);

        assertEquals(TestSuiteResults.ToolType.DAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Acunetix WVS", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.LDAP_INJECTION, result.get(44).get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.get(2629).get(0).getCWE());
    }
}
