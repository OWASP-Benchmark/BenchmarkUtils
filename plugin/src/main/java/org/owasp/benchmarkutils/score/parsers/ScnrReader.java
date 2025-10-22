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
package org.owasp.benchmarkutils.score.parsers;

import static java.lang.Integer.parseInt;

import java.text.SimpleDateFormat;
import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class ScnrReader extends Reader {

    // 2015-08-17T14:21:14+03:00
    private final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX");

    @Override
    public boolean canRead(ResultFile resultFile) {
        try {
            return isScnrJsonReport(resultFile) || isScnrXmlReport(resultFile);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean isScnrJsonReport(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile
                        .json()
                        .getJSONObject("options")
                        .getJSONObject("device")
                        .getString("user_agent")
                        .contains("SCNR::Engine")
                && resultFile.json().getJSONArray("issues").getJSONObject(0).has("description");
    }

    private boolean isScnrXmlReport(ResultFile resultFile) {
        return resultFile.isXml()
                && textContentOf(resultFile.xmlRootNode(), "options").contains("SCNR::Engine");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        if (resultFile.isJson()) {
            return parseJsonReport(resultFile);
        } else {
            return parseXmlReport(resultFile);
        }
    }

    private TestSuiteResults parseJsonReport(ResultFile resultFile) {
        TestSuiteResults tr = scnrTestSuiteResults();

        JSONObject json = resultFile.json();
        tr.setToolVersion(json.getString("version"));
        tr.setTime(json.getString("delta_time"));

        JSONArray arr = json.getJSONArray("issues");

        for (int i = 0; i < arr.length(); i++) {
            TestCaseResult tcr = parseJsonResult(arr.getJSONObject(i));

            if (tcr != null) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    private static TestSuiteResults scnrTestSuiteResults() {
        return new TestSuiteResults("SCNR", true, TestSuiteResults.ToolType.DAST);
    }

    private TestCaseResult parseJsonResult(JSONObject issue) {
        if (!issue.has("cwe") || issue.getInt("cwe") == 0) {
            return null;
        }

        int testNumber = testNumber(issue.getJSONObject("vector").getString("url"));

        TestCaseResult tcr = new TestCaseResult();

        tcr.setCWE(issue.getInt("cwe"));
        tcr.setNumber(testNumber);

        return tcr;
    }

    private TestSuiteResults parseXmlReport(ResultFile resultFile) {
        TestSuiteResults tr = scnrTestSuiteResults();

        Element xml = resultFile.xmlRootNode();

        tr.setToolVersion(textContentOf(xml, "version"));

        tr.setTime(
                formatTimeDelta(
                        textContentOf(xml, "start_datetime"),
                        textContentOf(xml, "finish_datetime")));

        Node issues = getNamedChild("issues", xml);

        for (Node issue : getNamedChildren("issue", issues)) {
            TestCaseResult tcr = parseXmlResult(issue);

            if (tcr != null) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    private String formatTimeDelta(String start, String end) {
        try {
            return TestSuiteResults.formatTime(
                    sdf.parse(end).getTime() - sdf.parse(start).getTime());
        } catch (Exception e) {
            return "Unknown";
        }
    }

    private static String textContentOf(Element xml, String key) {
        return getNamedChild(key, xml).getTextContent();
    }

    private static String textContentOf(Node node, String key) {
        return getNamedChild(key, node).getTextContent();
    }

    private TestCaseResult parseXmlResult(Node issue) {
        if (!hasNamedChild("cwe", issue) || parseInt(textContentOf(issue, "cwe")) == 0) {
            return null;
        }

        int testNumber =
                testNumber(getNamedChild("url", getNamedChild("vector", issue)).getTextContent());

        TestCaseResult tcr = new TestCaseResult();

        tcr.setCWE(parseInt(textContentOf(issue, "cwe")));
        tcr.setNumber(testNumber);

        return tcr;
    }
}
