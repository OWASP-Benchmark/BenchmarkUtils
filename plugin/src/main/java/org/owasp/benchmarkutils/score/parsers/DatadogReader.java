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
 * @author Joseba Ander Ruiz Ayesta
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.BufferedReader;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class DatadogReader extends Reader {

    private final Set<String> invalid = new HashSet<>();

    private static final String VERSION_LINE = "DATADOG TRACER CONFIGURATION {\"version\":\"";

    private static final String TYPE = "\"type\":\"";

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".log") && resultFile.line(0).contains("dd.trace");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Datadog", true, TestSuiteResults.ToolType.IAST);

        try (BufferedReader reader = new BufferedReader(new StringReader(resultFile.content()))) {
            String firstLine = reader.readLine();
            String[] lastLine = {""};
            String line = "";
            List<String> chunk = new ArrayList<>();
            while (line != null) {
                try {
                    line = reader.readLine();
                    if (line == null || line.startsWith("[dd.trace")) {
                        processChunk(chunk, tr, lastLine);
                    }
                    if (line != null) {
                        chunk.add(line);
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                }
            }
            tr.setTime(calculateTime(firstLine, lastLine[0]));
        }
        return tr;
    }

    private void processChunk(List<String> chunk, TestSuiteResults tr, String[] lastLine)
            throws Exception {
        String testNumber = "00001";

        String line = chunk.stream().collect(Collectors.joining(""));
        if (line.contains("_dd.iast.json")) {
            // ok, we're starting a new URL, so process this one and start the next
            // chunk
            process(tr, testNumber, Arrays.asList(line));
            chunk.clear();
            testNumber = "00000";
            String fname = "/" + BenchmarkScore.TESTCASENAME;
            int idx = line.indexOf(fname);
            if (idx != -1) {
                testNumber = line.substring(idx + fname.length(), idx + fname.length() + 5);
            }
            lastLine[0] = line;
        } else if (line.contains(VERSION_LINE)) {
            int pos = line.indexOf(VERSION_LINE) + VERSION_LINE.length();
            String version = line.substring(pos, line.indexOf('"', pos + 1));
            tr.setToolVersion(version);
        }
        chunk.clear();
    }

    private String calculateTime(final String firstLine, final String lastLine) {
        try {
            return calculateTime(firstLine, lastLine, 2);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String calculateTime(
            final String firstLine, final String lastLine, final int timeColumn)
            throws ParseException {
        try {
            String start = firstLine.split(" ")[timeColumn];
            String stop = lastLine.split(" ")[timeColumn];
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss:SSS");
            Date startTime = sdf.parse(start);
            Date stopTime = sdf.parse(stop);
            long startMillis = startTime.getTime();
            long stopMillis = stopTime.getTime();
            return (stopMillis - startMillis) / 1000 + " seconds";
        } catch (Exception ex) {
            System.err.println("Error parsing dates:" + firstLine + " and " + lastLine);
            return "0 seconds";
        }
    }

    private void process(final TestSuiteResults tr, String testNumber, final List<String> chunk)
            throws Exception {
        for (String line : chunk) {
            TestCaseResult tcr = new TestCaseResult();

            String fname = "/" + BenchmarkScore.TESTCASENAME;
            int idx = line.indexOf(fname);
            if (idx != -1) {
                testNumber = line.substring(idx + fname.length(), idx + fname.length() + 5);
            }

            int pos = line.indexOf(TYPE) + TYPE.length();
            String type = line.substring(pos, line.indexOf('"', pos + 1));

            try {
                Type t = Type.valueOf(type);
                tcr.setCWE(t.number);
                tcr.setCategory(t.id);

                try {
                    tcr.setNumber(Integer.parseInt(testNumber));
                } catch (NumberFormatException e) {
                    System.out.println("> Parse error: " + line);
                }

                if (tcr.getCWE() != 0) {
                    tr.put(tcr);
                }
            } catch (Exception e) {
                if (invalid.add(type)) {
                    System.out.println("Invalid type:" + type);
                }
            }
        }
    }

    private enum Type {
        COMMAND_INJECTION(78),
        WEAK_HASH("crypto-bad-mac", 328),
        WEAK_CIPHER("crypto-bad-ciphers", 327),
        HEADER_INJECTION(113),
        INSECURE_COOKIE("cookie-flags-missing", 614),
        LDAP_INJECTION(90),
        NO_HTTP_ONLY_COOKIE(1004),
        PATH_TRAVERSAL(22),
        REFLECTION_INJECTION(0),
        SQL_INJECTION(89),
        STACKTRACE_LEAK(209),
        TRUST_BOUNDARY_VIOLATION(501),
        WEAK_RANDOMNESS("crypto-weak-randomness", 330),
        XPATH_INJECTION(643),
        XSS("reflected-xss", 79);

        private final int number;

        private final String id;

        private Type(final int number) {
            this.number = number;
            id = name().toLowerCase().replaceAll("_", "-");
        }

        private Type(final String id, final int number) {
            this.number = number;
            this.id = id;
        }
    }
}
