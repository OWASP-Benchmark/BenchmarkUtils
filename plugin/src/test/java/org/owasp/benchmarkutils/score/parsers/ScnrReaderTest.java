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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Sascha Knoop
 * @created 2024
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

public class ScnrReaderTest extends ReaderTestBase {

    private ResultFile jsonResultFile;
    private ResultFile xmlResultFile;

    @BeforeEach
    void setUp() {
        jsonResultFile = TestHelper.resultFileOf("testfiles/Benchmark_SCNR.json");
        xmlResultFile = TestHelper.resultFileOf("testfiles/Benchmark_SCNR.xml");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyScnrReaderReportsCanReadAsTrueForJsonFile() {
        assertOnlyMatcherClassIs(this.jsonResultFile, ScnrReader.class);
    }

    @Test
    public void onlyScnrReaderReportsCanReadAsTrueForXmlFile() {
        assertOnlyMatcherClassIs(this.xmlResultFile, ScnrReader.class);
    }

    @Test
    void readerHandlesGivenJsonResultFile() throws Exception {
        ScnrReader reader = new ScnrReader();
        TestSuiteResults result = reader.parse(jsonResultFile);

        assertToolData(result);

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.SQL_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());
    }

    private static void assertToolData(TestSuiteResults result) {
        assertEquals(TestSuiteResults.ToolType.DAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("SCNR", result.getToolName());
        assertEquals("1.0dev", result.getToolVersion());
        assertEquals("12:34:56", result.getTime());
    }

    @Test
    void readerHandlesGivenXmlResultFile() throws Exception {
        ScnrReader reader = new ScnrReader();
        TestSuiteResults result = reader.parse(xmlResultFile);

        assertToolData(result);

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.get(2).get(0).getCWE());
    }
}
