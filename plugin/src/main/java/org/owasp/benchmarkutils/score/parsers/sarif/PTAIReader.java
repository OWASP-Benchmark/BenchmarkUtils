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
 * @author Alexey Zhukov
 * @created 2024
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.owasp.benchmarkutils.score.CweNumber;

public class PTAIReader extends SarifReader {

    static final int PTAI_CWE_EXTERNAL_FILEPATH_CONTROL = 73;
    static final int PTAI_CWE_BLIND_XPATH_INJECTION = 91;

    public PTAIReader() {
        super("Positive Technologies Application Inspector", true, CweSourceType.FIELD);
    }

    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case PTAI_CWE_EXTERNAL_FILEPATH_CONTROL:
                return CweNumber.PATH_TRAVERSAL;
            case PTAI_CWE_BLIND_XPATH_INJECTION:
                return CweNumber.XPATH_INJECTION;
        }
        return cwe;
    }
}
