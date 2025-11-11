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
 * @author David Anderson
 * @created 2024
 */
package org.owasp.benchmarkutils.entities;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class VerifyFixOutput {
    private String testCaseName;
    private ResponseInfo unfixedSafeResponseInfo;
    private ResponseInfo unfixedAttackResponseInfo;
    private ResponseInfo fixedSafeResponseInfo;
    private ResponseInfo fixedAttackResponseInfo;
    private boolean wasNotVerifiable;
    private boolean wasExploited;
    private boolean wasBroken;

    public String getTestCaseName() {
        return testCaseName;
    }

    public void setTestCaseName(String testCaseName) {
        this.testCaseName = testCaseName;
    }

    public ResponseInfo getUnfixedSafeResponseInfo() {
        return unfixedSafeResponseInfo;
    }

    public void setUnfixedSafeResponseInfo(ResponseInfo unfixedSafeResponseInfo) {
        this.unfixedSafeResponseInfo = unfixedSafeResponseInfo;
    }

    public ResponseInfo getUnfixedAttackResponseInfo() {
        return unfixedAttackResponseInfo;
    }

    public void setUnfixedAttackResponseInfo(ResponseInfo unfixedAttackResponseInfo) {
        this.unfixedAttackResponseInfo = unfixedAttackResponseInfo;
    }

    public ResponseInfo getFixedSafeResponseInfo() {
        return fixedSafeResponseInfo;
    }

    public void setFixedSafeResponseInfo(ResponseInfo fixedSafeResponseInfo) {
        this.fixedSafeResponseInfo = fixedSafeResponseInfo;
    }

    public ResponseInfo getFixedAttackResponseInfo() {
        return fixedAttackResponseInfo;
    }

    public void setFixedAttackResponseInfo(ResponseInfo fixedAttackResponseInfo) {
        this.fixedAttackResponseInfo = fixedAttackResponseInfo;
    }

    public boolean isWasNotVerifiable() {
        return wasNotVerifiable;
    }

    public void setWasNotVerifiable(boolean wasNotVerifiable) {
        this.wasNotVerifiable = wasNotVerifiable;
    }

    public boolean isWasExploited() {
        return wasExploited;
    }

    public void setWasExploited(boolean wasExploited) {
        this.wasExploited = wasExploited;
    }

    public boolean isWasBroken() {
        return wasBroken;
    }

    public void setWasBroken(boolean wasBroken) {
        this.wasBroken = wasBroken;
    }
}
