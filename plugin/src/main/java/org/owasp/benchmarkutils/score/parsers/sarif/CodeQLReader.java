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
 * @author Nipuna Weerasekara
 * @author Nicolas Couraud
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.owasp.benchmarkutils.score.CweNumber;

public class CodeQLReader extends SarifReader {

    public CodeQLReader() {
        super("CodeQL", false, CweSourceType.TAG);
    }

    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case 94: // js/unsafe-dynamic-method-access & others - Improves the tool's score
                return CweNumber.COMMAND_INJECTION; // Command Injection
            case 335: // java/predictable-seed - Improves the tool's score
                return CweNumber.WEAK_RANDOM; // Weak Random
        }
        return cwe;
    }
}
