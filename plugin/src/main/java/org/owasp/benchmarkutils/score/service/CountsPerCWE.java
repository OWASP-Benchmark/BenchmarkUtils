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
 * @author Dave Wichers
 * @created 2025
 */

/**
 * Instances of this class are used to keep track of the number True and False Positives for a CWE
 * in the expectedresults file.
 */
package org.owasp.benchmarkutils.score.service;

public class CountsPerCWE {

    int truePositiveCount;
    int falsePositiveCount;

    public int getTPCount() {
        return truePositiveCount;
    }

    public int getFPCount() {
        return falsePositiveCount;
    }
}
