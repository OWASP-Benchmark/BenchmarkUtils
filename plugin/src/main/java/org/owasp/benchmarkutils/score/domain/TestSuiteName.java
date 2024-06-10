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

public class TestSuiteName {

    private final String name;

    public TestSuiteName(String name) {
        this.name = name;
    }

    public String simpleName() {
        return name;
    }

    /**
     * If required, provide a more descriptive test suite name than the base, single word test suite
     * name.
     */
    public String fullName() {
        if ("Benchmark".equals(name)) {
            return "OWASP Benchmark";
        }

        return simpleName();
    }
}
