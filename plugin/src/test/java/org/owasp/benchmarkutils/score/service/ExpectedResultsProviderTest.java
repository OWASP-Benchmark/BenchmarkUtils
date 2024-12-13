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
package org.owasp.benchmarkutils.score.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestHelper;
import org.owasp.benchmarkutils.score.TestSuiteResults;

class ExpectedResultsProviderTest {

    private ResultFile simpleResultFile;
    private ResultFile extendedResultFile;

    @BeforeEach
    void setUp() {
        simpleResultFile = TestHelper.resultFileOf("expectedresults-1.2-simple.csv");
        extendedResultFile = TestHelper.resultFileOf("expectedresults-1.2-extended.csv");
    }

    @Test
    void providerHandlesGivenSimpleResultFile() throws Exception {
        TestSuiteResults result = ExpectedResultsProvider.parse(simpleResultFile);

        assertNull(result.getToolType());
        assertEquals("Expected", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.PATH_TRAVERSAL, result.get(1).get(0).getCWE());
        assertNull(result.get(1).get(0).getSource());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(2).get(0).getCWE());
        assertNull(result.get(2).get(0).getSource());
    }

    @Test
    void providerHandlesGivenExtendedResultFile() throws Exception {
        TestSuiteResults result = ExpectedResultsProvider.parse(extendedResultFile);

        assertNull(result.getToolType());
        assertEquals("Expected", result.getToolName());

        assertEquals(2, result.getTotalResults());

        assertEquals(CweNumber.PATH_TRAVERSAL, result.get(1).get(0).getCWE());
        assertEquals("RequestGetCookies.code", result.get(1).get(0).getSource());

        assertEquals(CweNumber.COMMAND_INJECTION, result.get(2).get(0).getCWE());
        assertEquals("RequestGetHeader.code", result.get(2).get(0).getSource());
    }
}
