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
 * @author ShiftLeft
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.BufferedReader;
import java.io.FileReader;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.TestSuiteResults.ToolType;

/*
 * This Reader was contributed by ShiftLeft and is used to parse a custom .csv file their custom scripts
 * produce. Each line of this file, which has to have the extension .sl, looks like this:
 *    #####,VulnType - where ##### is the Benchmark test case number, and
 *                     VulnType is a string that can be mapped to a CWE #.
 */

public class ShiftLeftReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".sl");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("ShiftLeft", true, ToolType.SAST);

        try (BufferedReader reader = new BufferedReader(new FileReader(resultFile.file()))) {
            String line;
            while ((line = reader.readLine()) != null) {

                String[] split = line.split(",");
                if (split.length != 2) {
                    throw new RuntimeException("Invalid line in SL result file.");
                }

                String category = split[1];

                TestCaseResult testCaseResult = new TestCaseResult();
                testCaseResult.setCategory(category);
                testCaseResult.setNumber(Integer.parseInt(split[0]));
                testCaseResult.setCWE(categoryToCWE(category));
                testCaseResult.setEvidence(line);

                tr.put(testCaseResult);
            }
        }

        return tr;
    }

    private int categoryToCWE(String category) {
        switch (category) {
            case "cmdi":
                return 78;
            case "crypto":
                return 327;
            case "hash":
                return 328;
            case "ldapi":
                return 90;
            case "pathtraver":
                return 22;
            case "securecookie":
                return 614;
            case "sqli":
                return 89;
            case "trustbound":
                return 501;
            case "weakrand":
                return 330;
            case "xpathi":
                return 643;
            case "xss":
                return 79;
            default:
                throw new RuntimeException("Unknown category: " + category);
        }
    }
}
