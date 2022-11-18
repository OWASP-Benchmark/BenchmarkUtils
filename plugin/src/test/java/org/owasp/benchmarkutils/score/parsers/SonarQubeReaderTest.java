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

public class SonarQubeReaderTest extends ReaderTestBase {

    private ResultFile pluginResultFile;

    @BeforeEach
    void setUp() {
        pluginResultFile =
                TestHelper.resultFileOf("testfiles/Benchmark_sonar-Java-Plugin-v3.14-1234.xml");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlySonarQubeReaderReportsCanReadAsTrueForPluginResultFile() {
        assertOnlyMatcherClassIs(this.pluginResultFile, SonarQubeReader.class);
    }

    @Test
    void readerHandlesGivenPluginResultFile() throws Exception {
        SonarQubeReader reader = new SonarQubeReader();
        TestSuiteResults result = reader.parse(pluginResultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertFalse(result.isCommercial());
        assertEquals("SonarQube Java Plugin", result.getToolName());
        assertEquals("0:20:34", result.getTime());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.WEAK_RANDOM, result.get(2).get(0).getCWE());
    }
}
