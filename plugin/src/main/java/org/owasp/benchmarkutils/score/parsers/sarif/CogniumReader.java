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
 * @author Cognium Labs
 * @created 2026
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;

/** Reader for <a href="https://cognium.dev">Cognium</a> SARIF results. */
public class CogniumReader extends SarifReader {

    private final Map<String, Integer> ruleCweMappings;

    public CogniumReader() {
        super("cognium", false, CweSourceType.CUSTOM);
        Map<String, Integer> mappings = new HashMap<>();
        mappings.put("sql_injection", CweNumber.SQL_INJECTION);
        mappings.put("command_injection", CweNumber.COMMAND_INJECTION);
        mappings.put("code_injection", CweNumber.CODE_INJECTION);
        mappings.put("path_traversal", CweNumber.PATH_TRAVERSAL);
        mappings.put("xss", CweNumber.XSS);
        mappings.put("ldap_injection", CweNumber.LDAP_INJECTION);
        mappings.put("xpath_injection", CweNumber.XPATH_INJECTION);
        mappings.put("weak_random", CweNumber.WEAK_RANDOM);
        mappings.put("weak_hash", CweNumber.WEAK_HASH_ALGO);
        mappings.put("weak_crypto", CweNumber.WEAK_CRYPTO_ALGO);
        mappings.put("insecure_cookie", CweNumber.INSECURE_COOKIE);
        mappings.put("trust_boundary", CweNumber.TRUST_BOUNDARY_VIOLATION);
        mappings.put("xxe", CweNumber.XXE);
        mappings.put("deserialization", CweNumber.INSECURE_DESERIALIZATION);
        mappings.put("external_taint_escape", CweNumber.SSRF);
        ruleCweMappings = Collections.unmodifiableMap(mappings);
    }

    @Override
    public Map<String, Integer> customRuleCweMappings(JSONObject tool) {
        return ruleCweMappings;
    }
}
