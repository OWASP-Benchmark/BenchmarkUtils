package org.owasp.benchmarkutils.entities;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CliRequest {
    String command;

    List<RequestVariable> args;

    public CliRequest(String command, List<RequestVariable> args) {
        super();
        this.command = command;
        this.args = new ArrayList<RequestVariable>(args);
    }

    public CliRequest(String command, RequestVariable arg) {
        super();
        this.command = command;
        // Make a copy of the given args list so that when setSafe() changes elements, the changes
        // do not affect other CliRequest objects.
        this.args = new ArrayList<RequestVariable>(Arrays.asList(arg));
    }

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
        this.args = new ArrayList<RequestVariable>(args);
    }

    //	public List<String> getExecuteArgs() {
    //    	List<String> executeArgs = Arrays.asList(getCommand().split(" "));
    //    	executeArgs.addAll(getArgs());
    //    	return executeArgs;
    //	}

    public String toString() {
        ArrayList<String> executeArgs = new ArrayList<>(Arrays.asList(command.split(" ")));
        for (RequestVariable arg : args) {
            executeArgs.add(arg.getValue());
        }
        return String.join(" ", executeArgs);
    }
}
