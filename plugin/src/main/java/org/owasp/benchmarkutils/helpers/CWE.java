/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https:/owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2024
 */
package org.owasp.benchmarkutils.helpers;

public class CWE {
    private final int CWENumber; // e.g., 79
    private final String
            description; // e.g., Improper Neutralization of Input During Web Page Generation

    // ('Cross-site Scripting')

    public CWE(int cwe, String description) {
        this.CWENumber = cwe;
        this.description = description;
    }

    public int getCWENumber() {
        return this.CWENumber;
    }

    /**
     * CWE Description, e.g., Improper Neutralization of Input During Web Page Generation
     * ('Cross-site Scripting')
     *
     * @return The long description of this CWE type.
     */
    public String getDescription() {
        return this.description;
    }
}
