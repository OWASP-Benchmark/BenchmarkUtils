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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CliRequest {
    private String command;

    private List<RequestVariable> args;

    private RequestVariable stdinData;

    public CliRequest() {}

    public CliRequest(String command, List<RequestVariable> args, RequestVariable stdinData) {
        super();
        this.command = command;
        if (args == null) {
            this.args = new ArrayList<RequestVariable>();
        } else {
            this.args = new ArrayList<RequestVariable>(args);
        }
        this.stdinData = stdinData;
    }

    //    public CliRequest(String command, RequestVariable arg, RequestVariable stdinData) {
    //        super();
    //        this.command = command;
    //        // Make a copy of the given args list so that when setSafe() changes elements, the
    // changes
    //        // do not affect other CliRequest objects.
    //        this.args = new ArrayList<RequestVariable>(Arrays.asList(arg));
    //        this.stdinData = stdinData;
    //    }

    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public List<RequestVariable> getArgs() {
        return args;
    }

    public void setArgs(List<RequestVariable> args) {
        if (args == null) {
            this.args = new ArrayList<RequestVariable>();
        } else {
            this.args = new ArrayList<RequestVariable>(args);
        }
    }

    //	public List<String> getExecuteArgs() {
    //    	List<String> executeArgs = Arrays.asList(getCommand().split(" "));
    //    	executeArgs.addAll(getArgs());
    //    	return executeArgs;
    //	}

    public RequestVariable getStdinData() {
        return stdinData;
    }

    public void setStdinData(RequestVariable stdinData) {
        this.stdinData = stdinData;
    }

    public String toString() {
        ArrayList<String> executeArgs = new ArrayList<>(Arrays.asList(command.split(" ")));
        for (RequestVariable arg : args) {
            executeArgs.add(arg.getValue());
        }
        String s = String.join(" ", executeArgs);
        if (getStdinData() != null) {
            s += " stdin: " + getStdinData().getValue();
        }
        return s;
    }
}
