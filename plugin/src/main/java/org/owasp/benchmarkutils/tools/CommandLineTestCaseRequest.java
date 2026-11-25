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
package org.owasp.benchmarkutils.tools;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.xml.bind.annotation.XmlAttribute;
import org.apache.hc.client5.http.classic.methods.HttpUriRequestBase;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;
import org.owasp.benchmarkutils.helpers.RequestVariable;

/**
 * A test case request that executes a command-line program instead of making an HTTP request. Used
 * for benchmarking non-web applications (e.g., Python scripts, CLI tools).
 *
 * <p>In the test suite XML, use {@code tcType="CLI"} to select this request type:
 *
 * <pre>{@code
 * <benchmarkTest tcType="CLI" tcName="PythonTest00001"
 *     tcCommand="python3" tcCommandArgs="test001.py"
 *     tcCategory="sqli" tcVulnerable="true"
 *     tcAttackSuccess="SQL injection detected" ...>
 *     <formparam name="input" value="' OR 1=1 --" safeValue="hello"/>
 * </benchmarkTest>
 * }</pre>
 *
 * <p>The {@code formparam} elements reuse the existing {@link RequestVariable} attack/safe switching
 * mechanism: their current values are appended as {@code --name value} arguments to the command.
 */
@XmlDiscriminatorValue("CLI")
public class CommandLineTestCaseRequest extends AbstractTestCaseRequest {

    private String command;
    private String commandArgs;
    private String commandDir;

    public CommandLineTestCaseRequest() {}

    @XmlAttribute(name = "tcCommand")
    public String getCommand() {
        return this.command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    @XmlAttribute(name = "tcCommandArgs")
    public String getCommandArgs() {
        return this.commandArgs;
    }

    public void setCommandArgs(String commandArgs) {
        this.commandArgs = commandArgs;
    }

    @XmlAttribute(name = "tcCommandDir")
    public String getCommandDir() {
        return this.commandDir;
    }

    public void setCommandDir(String commandDir) {
        this.commandDir = commandDir;
    }

    /**
     * Build the command line for execution.
     *
     * <p>Switches all {@link RequestVariable}s to safe or attack mode, then constructs the full
     * argument list: the executable, any base arguments, and each form parameter as {@code --name
     * value}.
     *
     * @param isSafe true for the safe (control) run, false for the attack run.
     * @return the command and arguments as a list suitable for {@link ProcessBuilder}.
     */
    public List<String> buildCommand(boolean isSafe) {
        setSafe(isSafe);

        List<String> cmd = new ArrayList<>();
        cmd.add(command);

        if (commandArgs != null && !commandArgs.trim().isEmpty()) {
            Collections.addAll(cmd, commandArgs.trim().split("\\s+"));
        }

        for (RequestVariable param : getFormParams()) {
            cmd.add("--" + param.getName());
            cmd.add(param.getValue());
        }

        return cmd;
    }

    /**
     * Returns an unmodifiable view of the command that would be executed. Useful for logging without
     * side effects on the safe/attack state.
     */
    public List<String> getLastBuiltCommand(boolean isSafe) {
        return Collections.unmodifiableList(buildCommand(isSafe));
    }

    // --- HTTP abstract method no-ops (required by AbstractTestCaseRequest) ---

    @Override
    void buildBodyParameters(HttpUriRequestBase request) {}

    @Override
    void buildCookies(HttpUriRequestBase request) {}

    @Override
    void buildHeaders(HttpUriRequestBase request) {}

    @Override
    void buildQueryString() {
        setQuery("");
    }

    @Override
    HttpUriRequestBase createRequestInstance(String URL) {
        return null;
    }
}
