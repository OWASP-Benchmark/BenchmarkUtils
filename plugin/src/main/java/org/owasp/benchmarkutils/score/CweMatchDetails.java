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
 * @author Dave Wichers
 * @created 2024
 */
package org.owasp.benchmarkutils.score;

/**
 * This class contains the details of how a tool's result matches to a particular test case. With
 * CWE parent/child matching, we want to record exactly how a tool's finding matched. Was it an
 * exact CWE match? Did it report a child CWE, or a parent CWE? And if it didn't match at all, then
 * those details aren't present.
 */
public class CweMatchDetails {

    // These document the expected results
    public final int expectedCWE; // The exact match CWE
    public boolean truePositive; // Is this test case a true or false positive

    // These are for the actual tool results
    public final boolean pass; // Did the tool pass the test case

    // These two values are only populated under two conditions, when the tool finds a True Positive
    // or reports a False Negative

    // The CWE the tool reported, could be exact, parent, or child CWE.
    public final int actualCWEreported; // -1 if not found
    // Empty string if exact match or no match. ChildOF if a child CWE, ParentOf if parent CWE
    public final String CWErelationship;

    public CweMatchDetails(
            int expectedCWE,
            boolean truePositive,
            boolean pass,
            int actualCWEreported,
            String CWErelationship) {
        this.expectedCWE = expectedCWE;
        this.truePositive = truePositive;
        this.pass = pass;
        this.actualCWEreported = actualCWEreported; // Suggest -1 if not found
        // Blank string if not found or exact CWE match
        this.CWErelationship = (CWErelationship == null ? "" : CWErelationship);
    }
}
