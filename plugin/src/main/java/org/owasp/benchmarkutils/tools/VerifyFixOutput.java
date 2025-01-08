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
package org.owasp.benchmarkutils.tools;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
public class VerifyFixOutput {
    private boolean wasNotVerfiable;
    private boolean wasExploited;
    private boolean wasBroken;

    public boolean isWasNotVerfiable() {
        return wasNotVerfiable;
    }

    public void setWasNotVerfiable(boolean wasNotVerfiable) {
        this.wasNotVerfiable = wasNotVerfiable;
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
