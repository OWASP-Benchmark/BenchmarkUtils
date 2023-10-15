package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.*;
import org.owasp.benchmarkutils.score.domain.TestSuiteResults;
import org.owasp.benchmarkutils.score.domain.ToolType;

public class SnykReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_Snyk-v1.json");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    void onlySnykReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, SnykReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        SnykReader reader = new SnykReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("Snyk", result.getToolName());

        assertEquals(2, result.getTotalResults());
        assertEquals(CweNumber.XSS, result.resultsFor(1).get(0).getCWE());
        assertEquals(CweNumber.SQL_INJECTION, result.resultsFor(2).get(0).getCWE());
    }
}
