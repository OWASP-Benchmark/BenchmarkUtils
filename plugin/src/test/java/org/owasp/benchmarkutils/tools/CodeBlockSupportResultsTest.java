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
 */
package org.owasp.benchmarkutils.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class CodeBlockSupportResultsTest {

    @Test
    void constructsSinkWithCategory() {
        CodeBlockSupportResults r = new CodeBlockSupportResults("MySink", "SINK", true);
        r.vulnCat = "sqli";

        assertEquals("MySink", r.name);
        assertEquals("SINK", r.type);
        assertTrue(r.truePositive);
        assertEquals("sqli", r.vulnCat);
    }

    @Test
    void isolationSetsAreInitializedEmpty() {
        CodeBlockSupportResults r = new CodeBlockSupportResults("test", "SOURCE", false);

        assertNotNull(r.fnTestCases);
        assertNotNull(r.isolatedFnCause);
        assertNotNull(r.isolatedFpCause);
        assertTrue(r.fnTestCases.isEmpty());
        assertTrue(r.isolatedFnCause.isEmpty());
        assertTrue(r.isolatedFpCause.isEmpty());
    }

    @Test
    void toIsolationStringForSinkIncludesCategory() {
        CodeBlockSupportResults r = new CodeBlockSupportResults("WeakCipher", "SINK", true);
        r.vulnCat = "crypto";
        r.isolatedFnCause.add("BenchmarkTest00001");
        r.isolatedFnCause.add("BenchmarkTest00002");

        String result = r.toIsolationString();

        assertTrue(result.contains("[SINK]"), "Should include type");
        assertTrue(result.contains("WeakCipher"), "Should include name");
        assertTrue(result.contains("(crypto)"), "Sink should include category");
        assertTrue(result.contains("2 FNs isolated"), "Should count FN causes");
    }

    @Test
    void toIsolationStringForSourceOmitsCategory() {
        CodeBlockSupportResults r = new CodeBlockSupportResults("HttpParam", "SOURCE", false);

        String result = r.toIsolationString();

        assertTrue(result.contains("[SOURCE]"));
        assertTrue(result.contains("HttpParam"));
        assertTrue(result.contains("0 FNs isolated"));
    }

    @Test
    void toIsolationStringForEmptyDataflowUsesNoDataFlowName() {
        CodeBlockSupportResults r = new CodeBlockSupportResults("", "DATAFLOW", false);

        String result = r.toIsolationString();

        assertTrue(
                result.contains("NoDataFlow"),
                "Empty dataflow name should display as NoDataFlow");
    }

    @Test
    void toIsolationStringIncludesFpCountWhenPresent() {
        CodeBlockSupportResults r = new CodeBlockSupportResults("SafeEncoder", "DATAFLOW", false);
        r.isolatedFpCause.add("BenchmarkTest00010");

        String result = r.toIsolationString();

        assertTrue(result.contains("1 FPs isolated"), "Should include FP isolation count");
    }

    @Test
    void toIsolationStringOmitsFpSectionWhenEmpty() {
        CodeBlockSupportResults r = new CodeBlockSupportResults("Sink1", "SINK", true);
        r.vulnCat = "xss";

        String result = r.toIsolationString();

        assertTrue(
                !result.contains("FPs isolated"),
                "Should not mention FPs when isolatedFpCause is empty");
    }
}
