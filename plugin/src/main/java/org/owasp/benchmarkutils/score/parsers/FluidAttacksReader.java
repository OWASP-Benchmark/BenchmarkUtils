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
 * @author https://github.com/kamadorueda
 * @created 2021
 */
package org.owasp.benchmarkutils.score.parsers;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.apache.commons.io.FilenameUtils;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class FluidAttacksReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith("csv")
                && resultFile
                        .line(0)
                        .trim()
                        .equals(
                                "title,cwe,description,cvss,finding,stream,kind,where,snippet,method");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Fluid Attacks", true, TestSuiteResults.ToolType.SAST);

        java.io.Reader inReader = new java.io.StringReader(resultFile.content());
        Iterable<CSVRecord> records = CSVFormat.RFC4180.withFirstRecordAsHeader().parse(inReader);

        for (CSVRecord record : records) {
            TestCaseResult testCaseResult = new TestCaseResult();
            // Read only useful rows of the csv results
            if (record.get("description").split("OWASP").length < 2) {
                continue;
            }
            String what = record.get("description").split("OWASP")[1];
            String cwe = record.get("cwe").split("-")[1];

            // Parse columns into the correct types
            String category = cweToCategory(cwe);
            String testCaseName = FilenameUtils.getBaseName(what);

            // We are only interested in results for the Benchmark test cases
            if (testCaseName.startsWith(BenchmarkScore.TESTCASENAME)) {
                testCaseResult.setCategory(category);
                testCaseResult.setCWE(categoryToExpectedCwe(category));
                testCaseResult.setNumber(
                        Integer.parseInt(
                                testCaseName.substring(
                                        testCaseName.length() - BenchmarkScore.TESTIDLENGTH,
                                        testCaseName.length())));
                testCaseResult.setTestCaseName(testCaseName);
                tr.put(testCaseResult);
            }
        }

        return tr;
    }

    private static Integer categoryToExpectedCwe(String cwe) {
        switch (cwe) {
            case "pathtraver":
                return 22;
            case "cmdi":
                return 78;
            case "xss":
                return 79;
            case "sqli":
                return 89;
            case "ldapi":
                return 90;
            case "crypto":
                return 327;
            case "hash":
                return 328;
            case "weakrand":
                return 330;
            case "trustbound":
                return 501;
            case "securecookie":
                return 614;
            case "xpathi":
                return 643;
            default:
                return 0;
        }
    }

    private static String cweToCategory(String cwe) {
        switch (cwe) {
            case "22":
                return "pathtraver";
            case "78":
                return "cmdi";
            case "79":
                return "xss";
            case "89":
                return "sqli";
            case "90":
                return "ldapi";
            case "310":
                return "crypto";
            case "327":
                return "crypto";
            case "328":
                return "hash";
            case "330":
                return "weakrand";
            case "501":
                return "trustbound";
            case "614":
                return "securecookie";
            case "643":
                return "xpathi";
            default:
                return "other";
        }
    }
}