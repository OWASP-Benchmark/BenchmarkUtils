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
 * @author Raj Barath
 * @created 2023
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

public class SnykReader extends SarifReader {

    public SnykReader() {
        super("SnykCode", true, CweSourceType.FIELD);
    }

    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case 121: // Snyk reports all cpp/BufferOverflow as CWE-121 Stack-based Buffer Overflow
                // even though it might also be on the heap. As such, we map it to the parent
                // of both
                return 119; // Improper Restriction of OPerations within Bounds of a Memory Buffer
        }
        return cwe;
    }
}
