package org.owasp.benchmarkutils.entities;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class CliRequest {
    private String command;

    private List<RequestVariable> args;

    private RequestVariable stdinData;

    public CliRequest(String command, List<RequestVariable> args, RequestVariable stdinData) {
        super();
        this.command = command;
        this.args = new ArrayList<RequestVariable>(args);
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
        this.args = new ArrayList<RequestVariable>(args);
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
