package org.owasp.benchmarkutils.helpers;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.Arrays;
import java.util.List;

public class CliFileExecutableTestCaseInput extends ExecutableTestCaseInput {
    public void execute() {
        List<String> executeArgs = Arrays.asList(getCommand());

        File argsFile = new File(TEST_SUITE_DIR, "args_file.txt");

        //      args_file = 'args_file.txt'
        //      with open(TEST_SUITE_DIR + args_file, 'w') as f:
        //          f.write(arg1)
        //      crawlArgs.extend([args_file])
        //      child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
        //      child.logfile = sys.stdout
        //      child.expect(pexpect.EOF)
        //      child.close()
        //      print("Return code: %d" % child.exitstatus)

        executeArgs.add(getPayload());
        executeArgs.add("-f");
        executeArgs.add(argsFile.getPath());
        try (PrintWriter writer = new PrintWriter(new FileWriter(argsFile))) {
            writer.print(getPayload());
        }

        ProcessBuilder builder = new ProcessBuilder(executeArgs);
        final Process process = builder.start();
        int exitValue = process.waitFor();
        System.out.printf("Program terminated with return code: %s%n", exitValue);
    }
}
