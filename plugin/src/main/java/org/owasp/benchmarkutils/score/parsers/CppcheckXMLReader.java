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
package org.owasp.benchmarkutils.score.parsers;

import java.util.List;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

/**
 * The Cppcheck XML reader parses the XML results file generated when you use the cppcheck analyzer
 * to analyze then export results to an XML file. The command is like: cppcheck . --enable=all --xml
 * 2> YOURFILENAME.xml. Other parameters are likely required to include support files (-I), or
 * possibly exclude certain source files (-i).
 */
public class CppcheckXMLReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        /*
         * XML file starts with:
         *    <?xml version="1.0" encoding="UTF-8"?>
         *      <results version="2">
         *        <cppcheck version="2.9" />
         *        <errors>
         *          <error id= ...
         */
        return resultFile.filename().endsWith(".xml") && resultFile.line(2).contains("cppcheck");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Cppcheck", true, TestSuiteResults.ToolType.SAST);

        // get and parse: <cppcheck version="2.9" />
        Node cppcheck = getNamedChild("cppcheck", resultFile.xmlRootNode());
        String version = getAttributeValue("version", cppcheck);
        tr.setToolVersion(version);

        Node errorsNode = getNamedChild("errors", resultFile.xmlRootNode());
        List<Node> errors = getNamedChildren("error", errorsNode);

        for (Node error : errors) {
            TestCaseResult tcr = new TestCaseResult();
            String filename = getAttributeValue("file0", error);
            if (filename == null) {

                String ruleid = getAttributeValue("id", error);
                switch (ruleid) {
                    case "ctunullpointer":
                    case "unusedFunction":
                        // For these rules, the file location is specified in a child node like
                        // this: <location
                        // file="testcases/CWE476_NULL_Pointer_Dereference/CWE476_NULL_Pointer_Dereference__char_41.c" line="28" column="22" info="Dereferencing argument data that is null"/>

                        Node locationNode = getNamedChild("location", error);
                        filename = getAttributeValue("file", locationNode);
                        if (filename == null) {
                            continue; // Skip to next error Node in for loop since finding is mapped
                            // to specific file.
                        }

                        // Drop through to if (isTestCaseFile(filename)) below
                        break;

                        // Check to see if is an 'information' level error like:  error:
                        // id="missingIncludeSystem" severity="information" msg="Include file:
                        // &lt;stdio.h&gt; not found. Please note: Cppcheck does not need standard
                        // library headers to get proper results."

                        // If so, don't generate a warning message
                    case "checkersReport":
                    case "missingIncludeSystem": // Had to add
                        // case "toomanyconfigs": // Have to add --force to command to address
                        // id="toomanyconfigs" severity="information" msg="Too many #ifdef
                        // configurations - cppcheck only checks 12 of 19 configurations. Use
                        // --force to check all configurations."
                        continue; // Skip to next error Node in for loop

                    default:
                        /* System.out.println(
                        "DRW: Node has no 'file0' attribute: "
                                + error
                                + " but has ruleid: "
                                + ruleid); */
                        continue; // Skip to next error Node in for loop
                }
            }

            if (isTestCaseFile(filename)) {
                tcr.setActualResultTestID(TestSuiteResults.getFileNameNoPath(filename));
                String cwe = getAttributeValue("cwe", error);
                if (cwe == null) {
                    String ruleid = getAttributeValue("id", error);
                    switch (ruleid) {
                        case "allocaCalled":
                            // Currently, do nothing. DRW TODO: This should maybe return the CWE for
                            // buffer overflow, or obsolete function.
                            // See: "Obsolete function &apos;alloca&apos; called. In C99 and later
                            // it is recommended to use a variable length array instead."
                            // verbose="The obsolete function &apos;alloca&apos; is called. In C99
                            // and later it is recommended to use a variable length array or a
                            // dynamically allocated array instead. The function &apos;alloca&apos;
                            // is dangerous for many reasons
                            // (http://stackoverflow.com/questions/1018853/why-is-alloca-not-considered-good-practice and http://linux.die.net/man/3/alloca).
                        case "missingOverride":
                            // Means Override annotation missing when overriding a method.
                        case "normalCheckLevelMaxBranches": // Limiting analysis of branches. Use
                            // --check-level=exhaustive to analyze
                            // all branches
                            break;
                        default:
                            System.err.println(
                                    "WARNING: no CWE value provided for error id: '"
                                            + ruleid
                                            + "' file: "
                                            + TestSuiteResults.getFileNameNoPath(filename));
                    }
                } else {
                    try {
                        tcr.setCWE(Integer.parseInt(cwe));
                        tr.put(tcr);
                    } catch (NumberFormatException e) {
                        String ruleid = getAttributeValue("id", error);
                        System.err.println(
                                "ERROR: error id: '"
                                        + ruleid
                                        + "' has non-integer CWE value of: "
                                        + cwe);
                    }
                }
            } else {
                // Do nothing. Skip results for non-test files.
            }
        }
        return tr;
    }
}
