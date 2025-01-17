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
 * @author Sascha Knoop
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ContrastScanReader extends SarifReader {

    public ContrastScanReader() {
        super("Contrast Scan", true, CweSourceType.CUSTOM);
    }

    @Override
    public Map<String, Integer> customRuleCweMappings(JSONObject driver) {
        Map<String, Integer> ruleCweMap = new HashMap<>();

        ruleCweMap.put("unsafe-code-execution", CweNumber.COMMAND_INJECTION);
        ruleCweMap.put("cmd-injection", CweNumber.COMMAND_INJECTION);
        ruleCweMap.put("cookie-flags-missing", CweNumber.INSECURE_COOKIE);
        ruleCweMap.put("crypto-bad-ciphers", CweNumber.WEAK_CRYPTO_ALGO);
        ruleCweMap.put("crypto-bad-mac", CweNumber.WEAK_HASH_ALGO);
        ruleCweMap.put("crypto-weak-randomness", CweNumber.WEAK_RANDOM);
        ruleCweMap.put("header-injection", CweNumber.HTTP_RESPONSE_SPLITTING);
        ruleCweMap.put("hql-injection", CweNumber.HIBERNATE_INJECTION);
        ruleCweMap.put("ldap-injection", CweNumber.LDAP_INJECTION);
        ruleCweMap.put("nosql-injection", CweNumber.SQL_INJECTION);
        ruleCweMap.put("path-traversal", CweNumber.PATH_TRAVERSAL);
        ruleCweMap.put("reflected-xss", CweNumber.XSS);
        ruleCweMap.put("sql-injection", CweNumber.SQL_INJECTION);
        ruleCweMap.put("trust-boundary-violation", CweNumber.TRUST_BOUNDARY_VIOLATION);
        ruleCweMap.put("xpath-injection", CweNumber.XPATH_INJECTION);
        ruleCweMap.put("xxe", CweNumber.XXE);
        ruleCweMap.put("autocomplete-missing", 522); // CWE-522 Insufficiently Protected Creds

        return ruleCweMap;
    }

    @Override
    public void setVersion(ResultFile resultFile, TestSuiteResults testSuiteResults) {
        // SARIF file contains several nulls as version, just ignoring it
    }
}
