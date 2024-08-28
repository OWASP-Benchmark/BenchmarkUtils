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
 * @created 2024
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
 * Reader for <a
 * href="https://www.synopsys.com/software-integrity/security-testing/dast.html">WhiteHat Dynamic
 * (DAST)</a> results.
 */
public class WhiteHatDynamicReader extends Reader {

    private final Map<String, Integer> categoryMappings = new HashMap<>();

    public WhiteHatDynamicReader() {
        categoryMappings.put("Directory Indexing", 548);
        categoryMappings.put("Insecure Indexing", 548);
        categoryMappings.put("Insufficient Authorization", 287);
        categoryMappings.put("Insufficient Process Validation", 424);
        categoryMappings.put("Path Traversal", 35);
        categoryMappings.put("Predictable Resource Location", 425);
        categoryMappings.put("URL Redirector Abuse", 601);
        categoryMappings.put("Cross Site Request Forgery", 352);
        categoryMappings.put("Insufficient Transport Layer Protection", 319);
        categoryMappings.put("Session Prediction", 330);
        categoryMappings.put("Application Code Execution", 94);
        categoryMappings.put("Cross Site Scripting", CweNumber.XSS);
        categoryMappings.put("HTTP Response Splitting", 113);
        categoryMappings.put("Improper Input Handling", 20);
        categoryMappings.put("LDAP Injection", CweNumber.LDAP_INJECTION);
        categoryMappings.put("Mail Command Injection", 77);
        categoryMappings.put("OS Command Injection", CweNumber.COMMAND_INJECTION);
        categoryMappings.put("Query Language Injection", 943);
        categoryMappings.put("SQL Injection", CweNumber.SQL_INJECTION);
        categoryMappings.put("SSI Injection", 97);
        categoryMappings.put("XML Injection", 91);
        categoryMappings.put("XPath Injection", CweNumber.XPATH_INJECTION);
        categoryMappings.put("XQuery Injection", 652);
        categoryMappings.put("OS Commanding", CweNumber.COMMAND_INJECTION);
        categoryMappings.put("Routing Detour", 610);
        categoryMappings.put("Cacheable Sensitive Response", 525);
        categoryMappings.put("Frameable Resource", 1021);
        categoryMappings.put("Abuse of Functionality", 840);
        categoryMappings.put("Brute Force", 799);
        categoryMappings.put("Clickjacking", 1021);
        categoryMappings.put("Insufficient Anti-automation", 799);
        categoryMappings.put("Application Misconfiguration", 16);
        categoryMappings.put("Autocomplete Attribute", 16);
        categoryMappings.put("Fingerprinting", 497);
        categoryMappings.put("Information Leakage", 200);
        categoryMappings.put("Non-HttpOnly Session Cookie", 1004);
        categoryMappings.put("Server Misconfiguration", 16);
        categoryMappings.put("Unsecured Session Cookie", CweNumber.INSECURE_COOKIE);
        categoryMappings.put("XML External Entities", CweNumber.XXE);
        categoryMappings.put("Missing Secure Headers", 693);
        categoryMappings.put("Unpatched Software", 1104);
        categoryMappings.put("Insufficient Authentication", 285);
        categoryMappings.put("Insufficient Password Policy Implementation", 521);
        categoryMappings.put("Insufficient Password Recovery", 640);
        categoryMappings.put("Insufficient Session Expiration", 613);
        categoryMappings.put("Session Fixation", 384);
        categoryMappings.put("Content Spoofing", 451);
        categoryMappings.put("Remote File Inclusion", 829);
        categoryMappings.put("Denial of Service", 400);
        categoryMappings.put("Buffer Overflow", 788);
    }

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).contains("Report As Of");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("WhiteHat Dynamic", true, TestSuiteResults.ToolType.DAST);

        try (CSVParser records = resultFile.csvRecordsSkipFirstRows(headerRow(resultFile))) {
            records.stream()
                    .filter(WhiteHatDynamicReader::isRelevant)
                    .forEach(r -> tr.put(toTestCaseResult(r)));
        }

        return tr;
    }

    private int headerRow(ResultFile resultFile) {
        List<String> rows = resultFile.contentAsRows();

        for (int i = 0; i < rows.size(); i++) {
            if (rows.get(i).startsWith("Vuln ID")) {
                return i;
            }
        }

        throw new RuntimeException("No header row found");
    }

    private static boolean isRelevant(CSVRecord r) {
        return extractFilenameWithoutEnding(r.get("Attack Vector Path"))
                .startsWith(BenchmarkScore.TESTCASENAME);
    }

    private TestCaseResult toTestCaseResult(CSVRecord record) {
        String filename = record.get("Attack Vector Path");
        String category = record.get("Class");

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
                "WARNING: WhiteHat result file contained unmapped category: " + category);
        return CweNumber.DONTCARE;
    }
}
