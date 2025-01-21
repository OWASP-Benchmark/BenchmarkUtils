package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

class VeracodeReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Veracode.xml");
    }

    @Test
    void onlyVeracodeReportCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, VeracodeReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        VeracodeReader reader = new VeracodeReader();
        TestSuiteResults result = reader.parse(this.resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Veracode SAST", result.getToolName());

        assertEquals(3, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.getTestCaseResults("7").get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.getTestCaseResults("8").get(0).getCWE());
    }
}
