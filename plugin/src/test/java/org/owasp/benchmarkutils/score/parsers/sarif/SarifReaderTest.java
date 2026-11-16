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
package org.owasp.benchmarkutils.score.parsers.sarif;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class SarifReaderTest {

    @ParameterizedTest(name = "{index} - extracts cwe number from input {0}")
    @ValueSource(
            strings = {
                "CWE-326",
                "CWE-326: Inadequate Encryption Strength",
                "external/cwe/cwe-326",
                "CWE:326"
            })
    void extractsCweNumberFromInput(String input) {
        assertEquals(326, SarifReader.extractCwe(input));
    }

    @Test
    void fallsBackToFilenameTimeWhenInvocationsArrayIsEmpty() throws Exception {
        String sarif =
                "{\"runs\": [{"
                        + "\"invocations\": [],"
                        + "\"tool\": {\"driver\": {\"name\": \"SomeTool\", \"rules\": []}},"
                        + "\"results\": []"
                        + "}]}";

        ResultFile resultFile = new ResultFile("Benchmark_SomeTool-90.sarif", sarif);
        SarifReader reader = new SarifReader("SomeTool", false, SarifReader.CweSourceType.TAG) {};

        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.formatTime(90_000), result.getTime());
    }
}
