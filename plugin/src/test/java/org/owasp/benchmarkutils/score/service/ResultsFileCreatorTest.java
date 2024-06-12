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
 * @created 2024
 */
package org.owasp.benchmarkutils.score.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.builder.ConfigurationBuilder;
import org.owasp.benchmarkutils.score.builder.TestCaseResultBuilder;
import org.owasp.benchmarkutils.score.builder.TestSuiteResultsBuilder;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;

class ResultsFileCreatorTest {

    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");

    private File tmpDir;

    @BeforeEach
    void setUp() throws IOException {
        tmpDir = Files.createTempDirectory("Benchmark.ResultsFileCreatorTest").toFile();
    }

    @Test
    void createsSimpleResultsFile() throws IOException {
        BenchmarkScore.config = ConfigurationBuilder.builder().build();

        TestSuiteResults results =
                TestSuiteResultsBuilder.builder()
                        .setTestSuiteVersion("1.2")
                        .setToolname("Simple Result File")
                        .setToolVersion("47.11")
                        .build();

        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00001")
                        .setTestNumber(1)
                        .setCategory("pathtraver")
                        .setCwe(CweNumber.PATH_TRAVERSAL)
                        .setTruePositive(true)
                        .setPassed(true)
                        .build());
        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00002")
                        .setTestNumber(2)
                        .setCategory("trustbound")
                        .setCwe(CweNumber.TRUST_BOUNDARY_VIOLATION)
                        .setTruePositive(false)
                        .setPassed(false)
                        .build());
        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00003")
                        .setTestNumber(3)
                        .setCategory("sqli")
                        .setCwe(CweNumber.SQL_INJECTION)
                        .setTruePositive(false)
                        .setPassed(true)
                        .build());
        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00004")
                        .setTestNumber(4)
                        .setCategory("cmdi")
                        .setCwe(CweNumber.COMMAND_INJECTION)
                        .setTruePositive(true)
                        .setPassed(false)
                        .build());

        ResultsFileCreator resultsFileCreator =
                new ResultsFileCreator(tmpDir, new TestSuiteName("TestSuite"));

        resultsFileCreator.createFor(results);

        String resultFile = resultsFileCreator.createFor(results);

        assertEquals("TestSuite_v1.2_Scorecard_for_Simple_Result_File_v47.11.csv", resultFile);

        File file = new File(tmpDir, resultFile);

        assertTrue(file.exists());

        List<String> lines = Files.readAllLines(file.toPath());

        assertEquals(5, lines.size());

        assertEquals(
                "# test name, category, CWE, real vulnerability, identified by tool, pass/fail, "
                        + "TestSuite version: 1.2, Actual results generated: "
                        + sdf.format(new Date()),
                lines.get(0));
        assertEquals("BenchmarkTest00001, pathtraver, 22, true, true, pass", lines.get(1));
        assertEquals("BenchmarkTest00002, trustbound, 501, false, true, fail", lines.get(2));
        assertEquals("BenchmarkTest00003, sqli, 89, false, false, pass", lines.get(3));
        assertEquals("BenchmarkTest00004, cmdi, 78, true, false, fail", lines.get(4));
    }

    @Test
    void createsFullDetailsResultFile() throws IOException {
        BenchmarkScore.config = ConfigurationBuilder.builder().build();

        TestSuiteResults results =
                TestSuiteResultsBuilder.builder()
                        .setTestSuiteVersion("1.2")
                        .setToolname("Full Details Result File")
                        .setToolVersion("47.11")
                        .build();

        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00001")
                        .setTestNumber(1)
                        .setCategory("pathtraver")
                        .setCwe(CweNumber.PATH_TRAVERSAL)
                        .setTruePositive(true)
                        .setPassed(true)
                        .setSource("Source1")
                        .setDataFlow("DataFlow1")
                        .setSink("Sink1")
                        .build());
        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00002")
                        .setTestNumber(2)
                        .setCategory("trustbound")
                        .setCwe(CweNumber.TRUST_BOUNDARY_VIOLATION)
                        .setTruePositive(false)
                        .setPassed(false)
                        .setSource("Source2")
                        .setDataFlow("DataFlow2")
                        .setSink("Sink2")
                        .build());
        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00003")
                        .setTestNumber(3)
                        .setCategory("sqli")
                        .setCwe(CweNumber.SQL_INJECTION)
                        .setTruePositive(false)
                        .setPassed(true)
                        .setSource("Source3")
                        .setDataFlow("DataFlow3")
                        .setSink("Sink3")
                        .build());
        results.put(
                TestCaseResultBuilder.builder()
                        .setTestCaseName("BenchmarkTest00004")
                        .setTestNumber(4)
                        .setCategory("cmdi")
                        .setCwe(CweNumber.COMMAND_INJECTION)
                        .setTruePositive(true)
                        .setPassed(false)
                        .setSource("Source4")
                        .setDataFlow("DataFlow4")
                        .setSink("Sink4")
                        .build());

        ResultsFileCreator resultsFileCreator =
                new ResultsFileCreator(tmpDir, new TestSuiteName("TestSuite"));

        String resultFile = resultsFileCreator.createFor(results);

        assertEquals(
                "TestSuite_v1.2_Scorecard_for_Full_Details_Result_File_v47.11.csv", resultFile);

        File file = new File(tmpDir, resultFile);

        assertTrue(file.exists());

        List<String> lines = Files.readAllLines(file.toPath());

        assertEquals(5, lines.size());

        assertEquals(
                "# test name, category, CWE, source, data flow, sink, real vulnerability, identified "
                        + "by tool, pass/fail, TestSuite version: 1.2, Actual results generated: "
                        + sdf.format(new Date()),
                lines.get(0));
        assertEquals(
                "BenchmarkTest00001, pathtraver, 22, Source1, DataFlow1, Sink1, true, true, pass",
                lines.get(1));
        assertEquals(
                "BenchmarkTest00002, trustbound, 501, Source2, DataFlow2, Sink2, false, true, fail",
                lines.get(2));
        assertEquals(
                "BenchmarkTest00003, sqli, 89, Source3, DataFlow3, Sink3, false, false, pass",
                lines.get(3));
        assertEquals(
                "BenchmarkTest00004, cmdi, 78, Source4, DataFlow4, Sink4, true, false, fail",
                lines.get(4));
    }
}
