package org.owasp.benchmarkutils.helpers;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.util.Arrays;
import java.util.List;

public class StdinExecutableTestCaseInput extends ExecutableTestCaseInput {
    public void execute() {
        List<String> executeArgs = Arrays.asList(getCommand());

        File argsFile = new File(TEST_SUITE_DIR, "args_file.txt");

        //      child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
        //      #child.interact()
        //      child.sendline(arg1)
        //      child.logfile = sys.stdout
        //      child.expect(pexpect.EOF)
        //      child.close()
        //      print("Return code: %d" % child.exitstatus)

        ProcessBuilder builder = new ProcessBuilder(executeArgs);
        final Process process = builder.start();
        OutputStream stdin = process.getOutputStream();
        InputStream stdout = process.getInputStream();

        BufferedReader reader = new BufferedReader(new InputStreamReader(stdout));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(stdin));

        writer.write(getPayload());
        writer.flush();
        writer.close();

        int exitValue = process.waitFor();
        System.out.printf("Program terminated with return code: %s%n", exitValue);
    }
}
