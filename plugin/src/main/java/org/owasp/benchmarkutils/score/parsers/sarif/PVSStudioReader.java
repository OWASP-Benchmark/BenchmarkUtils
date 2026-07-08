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
 * @author Cyril Yepifanov
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import org.owasp.benchmarkutils.score.CweNumber;

public class PVSStudioReader extends SarifReader {

    static final int PVS_CWE_OS_COMMAND_INJECTION = 77;
    static final int PVS_CWE_OS_ARGUMENT_INJECTION = 88;
    static final int PVS_CWE_HASH_ALGO_NOT_RECOMMENDED = 1240;

    static final String TOOL_NAME = "PVS-Studio";

    public PVSStudioReader() {
        super(TOOL_NAME, true, CweSourceType.TAG);
    }

    @Override
    public int mapCwe(int cwe) {
        switch (cwe) {
            case PVS_CWE_OS_COMMAND_INJECTION:
            case PVS_CWE_OS_ARGUMENT_INJECTION:
                return CweNumber.COMMAND_INJECTION;
            case PVS_CWE_HASH_ALGO_NOT_RECOMMENDED:
                return CweNumber.WEAK_HASH_ALGO;
        }
        return cwe;
    }
}
