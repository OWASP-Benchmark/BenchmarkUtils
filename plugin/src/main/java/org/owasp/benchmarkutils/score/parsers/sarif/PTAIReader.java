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
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class PTAIReader extends SarifReader {

    static final int PTAI_CWE_EXTERNAL_FILEPATH_CONTROL = 73;
    static final int PTAI_CWE_BLIND_XPATH_INJECTION = 91;

    static final String EXPECTED_TOOL_NAME = "Positive Technologies Application Inspector";
    static final String SHORTENED_TOOL_NAME = "PT Application Inspector";

    public PTAIReader() {
        super(EXPECTED_TOOL_NAME, true, CweSourceType.FIELD);
    }

    @Override
    public String toolName(ResultFile resultFile) {
        return SHORTENED_TOOL_NAME;
    }

    /**
     * SARIF report tool version field is too long as it contains build number. Shorten it to X.Y.Z
     */
    @Override
    public void setVersion(ResultFile resultFile, TestSuiteResults testSuiteResults) {
        super.setVersion(resultFile, testSuiteResults);
        String version = testSuiteResults.getToolVersion();
        String[] versionItems = version.split("\\.");
        if (versionItems.length < 4) return;
        testSuiteResults.setToolVersion(
                String.format("%s.%s.%s", versionItems[0], versionItems[1], versionItems[2]));
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
