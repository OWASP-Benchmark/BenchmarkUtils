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

import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlRootElement;
import org.owasp.benchmarkutils.entities.CliRequest;
import org.owasp.benchmarkutils.entities.RequestVariable;

@XmlRootElement(name = "CliRequest")
public class CliExecutor extends TestExecutor {
    CliRequest cliRequest;

    public CliExecutor() {}

    public CliExecutor(CliRequest cliRequest) {
        super();
        this.cliRequest = cliRequest;
    }

    public CliRequest getCliRequest() {
        return cliRequest;
    }

    public void setCliRequest(CliRequest cliRequest) {
        this.cliRequest = cliRequest;
    }

    public String getExecutorDescription() {
        List<String> commandTokens = new ArrayList<>();
        commandTokens.add(cliRequest.getCommand());
        for (RequestVariable requestVariable : cliRequest.getArgs()) {
            commandTokens.add(String.format("%s%n", requestVariable.getValue()));
        }

        return commandTokens.toString();
    }
}
