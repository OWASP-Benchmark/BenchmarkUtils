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

import javax.xml.bind.annotation.XmlElement;

public class CliResponseInfo extends ResponseInfo {

    private CliRequest request;

    public CliResponseInfo() {
        // Default is this is a normal, non-attack response
        super();
    }

    public CliResponseInfo(boolean attackRequest) {
        super(attackRequest);
    }

    @XmlElement(required = true)
    public CliRequest getRequest() {
        return request;
    }

    public void setRequest(CliRequest request) {
        this.request = request;
    }
}
