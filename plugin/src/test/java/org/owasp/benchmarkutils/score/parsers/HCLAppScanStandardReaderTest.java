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
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class HCLAppScanStandardReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile =
                TestHelper.resultFileOf("testfiles/Benchmark_HCLAppScanStandardReader-v10.0.6.xml");
    }

    @Test
    public void onlyHCLAppScanStandardReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, HCLAppScanStandardReader.class);
    }

    @Test
    void readerHandlesGivenV10ResultFile() throws Exception {
        HCLAppScanStandardReader reader = new HCLAppScanStandardReader();
        TestSuiteResults result = reader.parse(this.resultFile);

        assertEquals(TestSuiteResults.ToolType.DAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("HCL AppScan Standard", result.getToolName());
        assertEquals("10.0.6", result.getToolVersion());

        assertEquals(4, result.getTotalResults());

        assertEquals(CweNumber.SQL_INJECTION, result.getTestCaseResults("1").get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.getTestCaseResults("2").get(0).getCWE());
        assertEquals(CweNumber.INSECURE_COOKIE, result.getTestCaseResults("300").get(0).getCWE());
        assertEquals(CweNumber.INSECURE_COOKIE, result.getTestCaseResults("348").get(0).getCWE());
    }
}
