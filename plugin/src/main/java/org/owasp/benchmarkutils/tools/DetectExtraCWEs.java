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
 * <p>Implements Issue #6: Add extra CWEs found detector.
 * Detects vulnerabilities found by tools outside of the intentional test cases.
 *
 * <p>Normal mode: For each tool, report CWEs from the expected set that are detected in test cases
 * where that CWE is NOT expected (e.g., tool reports CWE-89 in a hash test case).
 *
 * <p>Hard mode: Report ANY CWE detected in a test case where that CWE is not expected, including
 * CWEs not in the benchmark's expected set at all.
 */
package org.owasp.benchmarkutils.tools;

import java.io.File;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.owasp.benchmarkutils.score.parsers.Reader;
import org.owasp.benchmarkutils.score.service.ExpectedResultsProvider;

public class DetectExtraCWEs {

    private File expectedResultsFile;
    private File resultsDir;
    private String mode = "both"; // "normal", "hard", or "both"

    private static class ExpectedTestCase {
        final String name;
        final String category;
        final int cwe;
        final boolean vulnerable;

        ExpectedTestCase(String name, String category, int cwe, boolean vulnerable) {
            this.name = name;
            this.category = category;
            this.cwe = cwe;
            this.vulnerable = vulnerable;
        }
    }

    private static class ExtraFinding {
        final String testName;
        final int reportedCWE;
        final int expectedCWE;
        final String type; // "CWE_MISMATCH" or "UNKNOWN_CWE"

        ExtraFinding(String testName, int reportedCWE, int expectedCWE, String type) {
            this.testName = testName;
            this.reportedCWE = reportedCWE;
            this.expectedCWE = expectedCWE;
            this.type = type;
        }
    }

    public void processCommandLineArgs(String[] args) {
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        Options options = new Options();
        options.addOption(
                Option.builder("e")
                        .longOpt("expected")
                        .desc("expectedresults CSV file")
                        .hasArg()
                        .required()
                        .build());
        options.addOption(
                Option.builder("r")
                        .longOpt("results")
                        .desc("directory containing raw tool result files")
                        .hasArg()
                        .required()
                        .build());
        options.addOption(
                Option.builder("m")
                        .longOpt("mode")
                        .desc("detection mode: normal, hard, or both (default: both)")
                        .hasArg()
                        .build());

        try {
            CommandLine line = parser.parse(options, args);

            String expectedPath = line.getOptionValue("e");
            expectedResultsFile = new File(expectedPath);
            if (!expectedResultsFile.exists()) {
                throw new RuntimeException(
                        "Expected results file not found: " + expectedPath);
            }

            String resultsPath = line.getOptionValue("r");
            resultsDir = new File(resultsPath);
            if (!resultsDir.exists() || !resultsDir.isDirectory()) {
                throw new RuntimeException(
                        "Results directory not found: " + resultsPath);
            }

            if (line.hasOption("m")) {
                mode = line.getOptionValue("m");
            }
        } catch (ParseException e) {
            formatter.printHelp("DetectExtraCWEs", options);
            throw new RuntimeException("Error parsing arguments: ", e);
        }
    }

    public void run() {
        try {
            // 1. Load expected results
            Map<Integer, ExpectedTestCase> expected = loadExpectedResults();
            Set<Integer> expectedCWEs = new HashSet<>();
            for (ExpectedTestCase tc : expected.values()) {
                expectedCWEs.add(tc.cwe);
            }
            System.out.println(
                    "Loaded " + expected.size() + " expected test cases with "
                            + expectedCWEs.size() + " distinct CWEs: " + expectedCWEs);

            // 2. Process each raw result file
            File[] resultFiles = resultsDir.listFiles(f -> f.isFile());
            if (resultFiles == null || resultFiles.length == 0) {
                System.out.println("ERROR: No result files found in: " + resultsDir);
                return;
            }

            for (File resultFile : resultFiles) {
                // Skip expected results files
                if (resultFile.getName().startsWith("expectedresults")) continue;

                try {
                    ResultFile rf = new ResultFile(resultFile);
                    Reader reader = null;
                    for (Reader r : Reader.allReaders()) {
                        if (r.canRead(rf)) {
                            reader = r;
                            break;
                        }
                    }
                    if (reader == null) continue;

                    TestSuiteResults toolResults = reader.parse(rf);
                    String toolName = toolResults.getToolName();
                    if (toolResults.getToolVersion() != null) {
                        toolName += " v" + toolResults.getToolVersion();
                    }

                    analyzeToolResults(toolName, toolResults, expected, expectedCWEs);
                } catch (Exception e) {
                    System.out.println(
                            "WARNING: Could not parse " + resultFile.getName()
                                    + ": " + e.getMessage());
                }
            }
        } catch (Exception e) {
            System.out.println("ERROR: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private void analyzeToolResults(
            String toolName,
            TestSuiteResults toolResults,
            Map<Integer, ExpectedTestCase> expected,
            Set<Integer> expectedCWEs) {

        List<ExtraFinding> normalFindings = new ArrayList<>();
        List<ExtraFinding> hardFindings = new ArrayList<>();

        // For each finding the tool reported
        for (int tc : toolResults.keySet()) {
            List<TestCaseResult> results = toolResults.get(tc);
            for (TestCaseResult tcr : results) {
                int reportedCWE = tcr.getCWE();
                if (reportedCWE <= 0) continue; // Skip unmapped findings

                ExpectedTestCase expectedTC = expected.get(tc);
                if (expectedTC == null) {
                    // Finding for a test case number not in the expected results
                    // (could be non-test file mapped to -1, or an invalid number)
                    continue;
                }

                // Check if the reported CWE matches the expected CWE for this test case
                if (reportedCWE != expectedTC.cwe) {
                    if (expectedCWEs.contains(reportedCWE)) {
                        // Normal: a known CWE detected in the wrong test case
                        normalFindings.add(
                                new ExtraFinding(
                                        expectedTC.name,
                                        reportedCWE,
                                        expectedTC.cwe,
                                        "CWE_MISMATCH"));
                    } else {
                        // Hard: a CWE not even in the benchmark's expected set
                        hardFindings.add(
                                new ExtraFinding(
                                        expectedTC.name,
                                        reportedCWE,
                                        expectedTC.cwe,
                                        "UNKNOWN_CWE"));
                    }
                }
            }
        }

        // Report
        boolean hasFindings =
                (!normalFindings.isEmpty() && ("normal".equals(mode) || "both".equals(mode)))
                        || (!hardFindings.isEmpty()
                                && ("hard".equals(mode) || "both".equals(mode)));

        if (!hasFindings) return;

        System.out.println("\n=== " + toolName + " ===");

        if ("normal".equals(mode) || "both".equals(mode)) {
            if (normalFindings.isEmpty()) {
                System.out.println("  NORMAL: No extra known-CWE findings.");
            } else {
                System.out.println(
                        "  NORMAL: Known CWEs in wrong test cases ("
                                + normalFindings.size() + " findings):");
                // Group by reported CWE for readability
                TreeMap<Integer, List<ExtraFinding>> byCWE = new TreeMap<>();
                for (ExtraFinding ef : normalFindings) {
                    byCWE.computeIfAbsent(ef.reportedCWE, k -> new ArrayList<>()).add(ef);
                }
                for (Map.Entry<Integer, List<ExtraFinding>> entry : byCWE.entrySet()) {
                    System.out.println(
                            "    CWE-" + entry.getKey() + " found in "
                                    + entry.getValue().size() + " non-matching test cases:");
                    for (ExtraFinding ef : entry.getValue()) {
                        System.out.println(
                                "      " + ef.testName + " (expected CWE-" + ef.expectedCWE + ")");
                    }
                }
            }
        }

        if ("hard".equals(mode) || "both".equals(mode)) {
            if (hardFindings.isEmpty()) {
                System.out.println("  HARD: No extra non-benchmark CWE findings.");
            } else {
                System.out.println(
                        "  HARD: Non-benchmark CWEs detected ("
                                + hardFindings.size() + " findings):");
                TreeMap<Integer, List<ExtraFinding>> byCWE = new TreeMap<>();
                for (ExtraFinding ef : hardFindings) {
                    byCWE.computeIfAbsent(ef.reportedCWE, k -> new ArrayList<>()).add(ef);
                }
                for (Map.Entry<Integer, List<ExtraFinding>> entry : byCWE.entrySet()) {
                    System.out.println(
                            "    CWE-" + entry.getKey() + " found in "
                                    + entry.getValue().size() + " test cases:");
                    for (ExtraFinding ef : entry.getValue()) {
                        System.out.println(
                                "      " + ef.testName + " (expected CWE-" + ef.expectedCWE + ")");
                    }
                }
            }
        }
    }

    private Map<Integer, ExpectedTestCase> loadExpectedResults() throws Exception {
        Map<Integer, ExpectedTestCase> expected = new HashMap<>();
        try (FileReader fileReader = new FileReader(expectedResultsFile);
                CSVParser parser =
                        CSVFormat.Builder.create().setHeader().build().parse(fileReader)) {

            // Detect test suite name from header
            String testCaseName = null;
            for (String header : parser.getHeaderMap().keySet()) {
                if (header.contains(ExpectedResultsProvider.PREFIX)) {
                    int idx = header.indexOf(ExpectedResultsProvider.PREFIX);
                    testCaseName = header.substring(0, idx).trim() + BenchmarkScore.TEST;
                    BenchmarkScore.TESTCASENAME = testCaseName;
                    break;
                }
            }
            if (testCaseName == null) {
                throw new RuntimeException(
                        "Could not detect test suite name from expected results CSV header");
            }

            for (CSVRecord record : parser) {
                String name = record.get(ExpectedResultsProvider.TEST_NAME);
                if (!name.startsWith(testCaseName)) continue;

                String category = record.get(ExpectedResultsProvider.CATEGORY);
                boolean vulnerable =
                        Boolean.parseBoolean(
                                record.get(ExpectedResultsProvider.REAL_VULNERABILITY));
                int cwe = Integer.parseInt(record.get(ExpectedResultsProvider.CWE));
                int number =
                        org.owasp.benchmarkutils.score.parsers.Reader.testNumber(
                                name, testCaseName);

                expected.put(number, new ExpectedTestCase(name, category, cwe, vulnerable));
            }
        }
        return expected;
    }

    public static void main(String[] args) {
        DetectExtraCWEs detector = new DetectExtraCWEs();
        detector.processCommandLineArgs(args);
        detector.run();
    }
}
