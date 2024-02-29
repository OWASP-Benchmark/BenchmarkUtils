package org.owasp.benchmarkutils.tools;

import java.util.ArrayList;
import java.util.List;
import org.owasp.benchmarkutils.entities.CliRequest;
import org.owasp.benchmarkutils.entities.RequestVariable;

public class CliExecutor implements TestExecutor {
    CliRequest cliRequest;

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
