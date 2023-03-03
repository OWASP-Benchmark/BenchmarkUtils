package org.owasp.benchmarkutils.score.parsers;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VeracodeReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Veracode.xml");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    void onlyVeracodeReportCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, VeracodeReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        VeracodeReader reader = new VeracodeReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Veracode SAST", result.getToolName());

        assertEquals(3, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(7).get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.get(8).get(0).getCWE());
    }
}
