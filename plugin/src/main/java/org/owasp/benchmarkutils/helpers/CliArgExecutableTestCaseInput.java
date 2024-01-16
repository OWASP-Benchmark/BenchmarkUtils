package org.owasp.benchmarkutils.helpers;

import java.util.Arrays;
import java.util.List;

public class CliArgExecutableTestCaseInput extends ExecutableTestCaseInput {
    public void execute() {
        List<String> executeArgs = Arrays.asList(getCommand());

        //          crawlArgs.extend([arg1])
        //          child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
        //          child.logfile = sys.stdout
        //          child.expect(pexpect.EOF)
        //          child.close()
        //          print("Return code: %d" % child.exitstatus)

        executeArgs.add(getPayload());
        ProcessBuilder builder = new ProcessBuilder(executeArgs);
        final Process process = builder.start();
        int exitValue = process.waitFor();
        System.out.printf("Program terminated with return code: %s%n", exitValue);
    }
}
