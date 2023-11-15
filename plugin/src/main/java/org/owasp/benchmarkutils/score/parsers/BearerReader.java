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
 */
package org.owasp.benchmarkutils.score.parsers;

import java.util.Objects;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class BearerReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.json().has("findings")
                && resultFile.json().has("source")
                && Objects.equals(resultFile.json().getString("source"), "Bearer");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("Bearer", false, TestSuiteResults.ToolType.SAST);

        JSONArray results = resultFile.json().getJSONArray("findings");
        tr.setToolVersion(resultFile.json().getString("version"));

        // results
        for (int i = 0; i < results.length(); i++) {
            TestCaseResult tcr = parseBearerFindings(results.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private int translate(int cwe) {
        switch (cwe) {
            case 327:
                return CweNumber.WEAK_HASH_ALGO;
            default:
                return cwe;
        }
    }

    private TestCaseResult parseBearerFindings(JSONObject result) {
        /*
         * {
         * "cwe_ids": ["78"],
         * "id": "java_lang_os_command_injection",
         * "title": "Command injection vulnerability detected.",
         * "description":
         * "## Description\n\nUsing external or user-defined input directly in an OS command can allow attackers to perform dangerous commands on the operating system.\n\n## Remediations\n\n❌ Avoid using OS commands, with or without dynamic input, wherever possible. For example, look for an equivalent library or function to use instead.\n\n✅ For dynamic input, rely on hardcoded values wherever possible\n\n```java\n  String filePattern = \"*.json\";\n  if request.getParameter(\"format\") == \"xml\" {\n    filePattern = \"*.xml\"\n  }\n\n  Process process = Runtime.getRuntime().exec(\"ls /myDir/\" + extension);\n```\n\n## Resources\n- [OWASP command injection explained](https://owasp.org/www-community/attacks/Command_Injection)\n"
         * ,
         * "documentation_url":
         * "https://docs.bearer.com/reference/rules/java_lang_os_command_injection",
         * "line_number": 61,
         * "full_filename":
         * "../../OWASP/BenchmarkJava/src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00007.java",
         * "filename":
         * "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00007.java",
         * "category_groups": ["PII", "Personal Data"],
         * "source": {
         * "start": 61,
         * "end": 61,
         * "column": {
         * "start": 25,
         * "end": 46
         * }
         * },
         * "sink": {
         * "start": 61,
         * "end": 61,
         * "column": {
         * "start": 25,
         * "end": 46
         * },
         * "content": "r.exec(args, argsEnv)"
         * },
         * "parent_line_number": 61,
         * "snippet": "r.exec(args, argsEnv)",
         * "fingerprint": "4b44f26ced1d38c01bc3fe4275b3a142_0",
         * "old_fingerprint": "d45907bfb55a9cd885577ae854996b20_2",
         * "code_extract": "            Process p = r.exec(args, argsEnv);",
         * "severity": "high"
         * },
         */
        try {
            String className = result.getString("filename");
            className = (className.substring(className.lastIndexOf('/') + 1)).split("\\.")[0];
            if (className.startsWith(BenchmarkScore.TESTCASENAME)) {
                TestCaseResult tcr = new TestCaseResult();

                // CWE
                String cweString = result.getJSONArray("cwe_ids").getString(0);
                int cwe = Integer.parseInt(cweString);

                try {
                    cwe = translate(cwe);
                } catch (NumberFormatException ex) {
                    System.out.println(
                            "CWE # not parseable from: " + result.getJSONObject("cwe_ids"));
                }

                // evidence
                String evidence = result.getString("id");

                tcr.setCWE(cwe);
                tcr.setEvidence(evidence);
                tcr.setConfidence(0);
                tcr.setNumber(testNumber(className));

                return tcr;
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
