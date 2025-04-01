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
 * @author Dave Wichers
 * @created 2025
 */
package org.owasp.benchmarkutils.score.parsers.csv;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.parsers.Reader;

/**
 * Reader for <a href="https://semgrep.dev/orgs/YOUR_org/findings">SemGrep</a> results downloaded
 * via: "Download findings as CSV" button, next to Sort menu.
 */
public class SemgrepCSVReader extends Reader {

    private final Map<String, Integer> categoryMappings = new HashMap<>();

    // Mapping/explanation of SemGrep rules can be found here, for example:
    // https://semgrep.dev/r?q=java.servlets.security.tainted-cmd-from-http-request.tainted-cmd-from-http-request
    public SemgrepCSVReader() {
        categoryMappings.put(
                "java.lang.security.audit.active-debug-code-printstacktrace.active-debug-code-printstacktrace",
                209); // CWE-209: Generation of Error Message Containing Sensitive Information
        categoryMappings.put(
                "java.servlets.security.tainted-cmd-from-http-request.tainted-cmd-from-http-request",
                CweNumber.COMMAND_INJECTION);
        categoryMappings.put(
                "java.lang.security.audit.command-injection-process-builder.command-injection-process-builder",
                CweNumber.COMMAND_INJECTION);
        categoryMappings.put(
                "java.lang.security.audit.tainted-cmd-from-http-request.tainted-cmd-from-http-request",
                CweNumber.COMMAND_INJECTION);
        categoryMappings.put(
                "java.servlets.security.tainted-cmd-from-http-request-deepsemgrep.tainted-cmd-from-http-request-deepsemgrep",
                CweNumber.COMMAND_INJECTION);
        categoryMappings.put(
                "python.django.security.django-no-csrf-token.django-no-csrf-token", CweNumber.CSRF);
        categoryMappings.put(
                "java.lang.security.httpservlet-path-traversal.httpservlet-path-traversal",
                CweNumber.PATH_TRAVERSAL);
        categoryMappings.put(
                "java.servlets.security.httpservlet-path-traversal-deepsemgrep.httpservlet-path-traversal-deepsemgrep",
                CweNumber.PATH_TRAVERSAL);
        categoryMappings.put(
                "java.servlets.security.httpservlet-path-traversal.httpservlet-path-traversal",
                CweNumber.PATH_TRAVERSAL);
        categoryMappings.put(
                "java.lang.security.audit.tainted-ldapi-from-http-request.tainted-ldapi-from-http-request",
                CweNumber.LDAP_INJECTION);
        categoryMappings.put(
                "java.servlets.security.tainted-ldapi-from-http-request.tainted-ldapi-from-http-request",
                CweNumber.LDAP_INJECTION);
        categoryMappings.put(
                "java.servlets.security.tainted-ldapi-from-http-request-deepsemgrep.tainted-ldapi-from-http-request-deepsemgrep",
                CweNumber.LDAP_INJECTION);
        categoryMappings.put(
                "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli", CweNumber.SQL_INJECTION);
        categoryMappings.put(
                "java.lang.security.audit.sqli.tainted-sql-from-http-request.tainted-sql-from-http-request",
                CweNumber.SQL_INJECTION);
        categoryMappings.put(
                "java.lang.security.audit.tainted-session-from-http-request.tainted-session-from-http-request",
                CweNumber.TRUST_BOUNDARY_VIOLATION);
        categoryMappings.put(
                "java.servlets.security.tainted-session-from-http-request.tainted-session-from-http-request",
                CweNumber.TRUST_BOUNDARY_VIOLATION);
        categoryMappings.put(
                "java.servlets.security.tainted-session-from-http-request-deepsemgrep.tainted-session-from-http-request-deepsemgrep",
                CweNumber.TRUST_BOUNDARY_VIOLATION);
        categoryMappings.put(
                "java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request",
                CweNumber.XPATH_INJECTION);
        categoryMappings.put(
                "java.servlets.security.tainted-xpath-from-http-request.tainted-xpath-from-http-request",
                CweNumber.XPATH_INJECTION);
        categoryMappings.put(
                "java.servlets.security.tainted-xpath-from-http-request-deepsemgrep.tainted-xpath-from-http-request-deepsemgrep",
                CweNumber.XPATH_INJECTION);
        categoryMappings.put(
                "java.lang.security.audit.xss.no-direct-response-writer.no-direct-response-writer",
                CweNumber.XSS);
        categoryMappings.put(
                "java.servlets.security.servletresponse-writer-xss.servletresponse-writer-xss",
                CweNumber.XSS);
        categoryMappings.put(
                "java.servlets.security.servletresponse-writer-xss-deepsemgrep.servletresponse-writer-xss-deepsemgrep",
                CweNumber.XSS);
        categoryMappings.put(
                "java.lang.security.audit.cookie-missing-httponly.cookie-missing-httponly",
                CweNumber.COOKIE_WITHOUT_HTTPONLY);
        categoryMappings.put(
                "java.servlets.security.audit.cookie-missing-httponly.cookie-missing-httponly",
                CweNumber.COOKIE_WITHOUT_HTTPONLY);
        categoryMappings.put(
                "java.lang.security.audit.cookie-missing-secure-flag.cookie-missing-secure-flag",
                CweNumber.INSECURE_COOKIE);
        categoryMappings.put(
                "java.servlets.security.audit.cookie-secure-flag-false.cookie-secure-flag-false",
                CweNumber.INSECURE_COOKIE);
        categoryMappings.put(
                "java.servlets.security.audit.cookie-missing-samesite.cookie-missing-samesite",
                1275); //  CWE-1275: Sensitive Cookie with Improper SameSite Attribute
        categoryMappings.put(
                "java.lang.security.audit.crypto.des-is-deprecated.des-is-deprecated",
                CweNumber.WEAK_CRYPTO_ALGO);
        categoryMappings.put(
                "java.lang.security.audit.crypto.desede-is-deprecated.desede-is-deprecated",
                CweNumber.WEAK_CRYPTO_ALGO);
        categoryMappings.put(
                "java.lang.security.audit.crypto.use-of-md5.use-of-md5", CweNumber.WEAK_HASH_ALGO);
        categoryMappings.put(
                "java.lang.security.audit.crypto.use-of-sha1.use-of-sha1",
                CweNumber.WEAK_HASH_ALGO);
        categoryMappings.put(
                "java.lang.security.audit.crypto.weak-random.weak-random", CweNumber.WEAK_RANDOM);
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).contains("Semgrep Platform Link");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Semgrep", false, TestSuiteResults.ToolType.SAST);

        try (CSVParser records = resultFile.csvRecordsSkipFirstRows(headerRow(resultFile))) {
            records.stream()
                    .filter(SemgrepCSVReader::isRelevant)
                    .forEach(r -> tr.put(toTestCaseResult(r)));
        }

        return tr;
    }

    private int headerRow(ResultFile resultFile) {
        List<String> rows = resultFile.contentAsRows();

        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).startsWith("Id")) {
                return i;
            }
        }

        throw new RuntimeException("No header row found");
    }

    private static boolean isRelevant(CSVRecord r) {
        return extractFilenameWithoutEnding(r.get("Line Of Code Url"))
                .startsWith(BenchmarkScore.TESTCASENAME);
    }

    private TestCaseResult toTestCaseResult(CSVRecord record) {
        String filename = record.get("Line Of Code Url");
        String category = record.get("Rule Name");

        TestCaseResult tcr = new TestCaseResult();

        tcr.setCategory(category);
        tcr.setCWE(cweLookup(category));
        tcr.setNumber(testNumber(filename));

        return tcr;
    }

    private int cweLookup(String category) {
        if (categoryMappings.containsKey(category)) {
            return categoryMappings.get(category);
        }

        System.out.println(
                "WARNING: SemGrep CSV results file contained unmapped category: " + category);
        return CweNumber.DONTCARE;
    }
}
