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
 * @author TheAuditorTool
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ShiftLeftReaderTest extends ReaderTestBase {

    @TempDir Path tempDir;

    private ResultFile createSlFile(String content) throws Exception {
        File slFile = tempDir.resolve("Benchmark_ShiftLeft.sl").toFile();
        Files.writeString(slFile.toPath(), content);
        return new ResultFile(slFile);
    }

    @Test
    void readerHandlesKnownCategories() throws Exception {
        ResultFile resultFile = createSlFile("00001,sqli\n00002,xss\n");

        ShiftLeftReader reader = new ShiftLeftReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertTrue(result.isCommercial());
        assertEquals("ShiftLeft", result.getToolName());
        assertEquals(2, result.getTotalResults());
        assertEquals(CweNumber.SQL_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.XSS, result.get(2).get(0).getCWE());
    }

    @Test
    void unknownCategoryReturnsZeroInsteadOfThrowing() throws Exception {
        ResultFile resultFile = createSlFile("00003,unknowncategory\n");

        ShiftLeftReader reader = new ShiftLeftReader();

        TestSuiteResults result =
                assertDoesNotThrow(
                        () -> reader.parse(resultFile),
                        "Unknown category must not throw RuntimeException");

        assertEquals(1, result.getTotalResults());
        assertEquals(0, result.get(3).get(0).getCWE(), "Unknown category should map to CWE 0");
    }
}
