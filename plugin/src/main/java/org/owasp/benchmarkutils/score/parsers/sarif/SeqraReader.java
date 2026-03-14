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
 * @author Seqra Team
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.owasp.benchmarkutils.score.CweNumber;

/**
 * This reader is made for Seqra, a security static analysis tool. It uses the SARIF file produced
 * by the tool.
 */
public class SeqraReader extends SarifReader {

    public SeqraReader() {
        super("Seqra", false, CweSourceType.TAG);
    }

    /**
     * Maps Seqra CWE numbers to Benchmark expected CWEs.
     *
     * <p>The SarifReader base class only uses the first CWE tag from each rule. Some Seqra rules
     * have multiple CWE tags where the first one doesn't match Benchmark's expected CWE. This
     * method provides ad-hoc mappings for such cases.
     *
     * <p>Example: The rule "java.security.cookie-issecure-false" has tags [CWE-319, CWE-614]. The
     * parser picks CWE-319 (Cleartext Transmission), but Benchmark expects CWE-614 (Insecure
     * Cookie) for the "securecookie" category.
     */
    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case 319:
                // cookie-issecure-false rule has [CWE-319, CWE-614]
                // Benchmark expects CWE-614 for securecookie category
                return CweNumber.INSECURE_COOKIE;
            default:
                return cwe;
        }
    }
}
