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
package org.owasp.benchmarkutils.score.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class TestSuiteNameTest {

    @Test
    void returnsSimpleName() {
        assertEquals("SimpleName", new TestSuiteName("SimpleName").simpleName());
        assertEquals("Benchmark", new TestSuiteName("Benchmark").simpleName());
    }

    @Test
    void returnsFixedFullNameForBenchmark() {
        assertEquals("OWASP Benchmark", new TestSuiteName("Benchmark").fullName());
    }

    @Test
    void returnsSimpleNameForFullNameWhenNotBenchmark() {
        assertEquals("SimpleName", new TestSuiteName("SimpleName").fullName());
    }
}
