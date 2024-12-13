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

import org.owasp.benchmarkutils.score.CweNumber;

public class SnykReader extends SarifReader {

    public SnykReader() {
        super("SnykCode", true, CweSourceType.FIELD);
    }

    @Override
    public int mapCwe(int cwe) {
        if (cwe == CweNumber.PASSWORD_HASH_WITH_INSUFFICIENT_COMPUTATIONAL_EFFORT) {
            return CweNumber.WEAK_HASH_ALGO;
        }

        if (cwe == CweNumber.RELATIVE_PATH_TRAVERSAL) {
            return CweNumber.PATH_TRAVERSAL;
        }

        return super.mapCwe(cwe);
    }
}
