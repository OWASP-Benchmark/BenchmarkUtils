package org.owasp.benchmarkutils.entities;

import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("Stdin")
public class StdinExecutableTestCaseInput extends ExecutableTestCaseInput {
    public RequestVariable getStdinData() {
        // FIXME
        return null;
    }

    public CliRequest buildAttackRequest() {
        //		ArrayList<String> executeArgs = new ArrayList<>();
        //		// FIXME: This will break if the command string has arguments that contain spaces.
        //		executeArgs.addAll(Arrays.asList(getCommand().split(" ")));
        //		executeArgs.addAll(getArgs());

        setSafe(false);
        return new CliRequest(getCommand(), getStdinData());
    }

    public CliRequest buildSafeRequest() {
        setSafe(true);
        return new CliRequest(getCommand(), getStdinData());
    }

    public void setSafe(boolean isSafe) {
        //        //        this.isSafe = isSafe;
        //        for (RequestVariable arg : getArgs()) {
        //            // setSafe() considers whether attack and safe values exist for this parameter
        // before
        //            // setting isSafe true or false. So you don't have to check that here.
        //            arg.setSafe(isSafe);
        //        }
    }

    //    public void execute() {
    //        List<String> executeArgs = Arrays.asList(getCommand());
    //
    //        File argsFile = new File(TEST_SUITE_DIR, "args_file.txt");
    //
    //        //      child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
    //        //      #child.interact()
    //        //      child.sendline(arg1)
    //        //      child.logfile = sys.stdout
    //        //      child.expect(pexpect.EOF)
    //        //      child.close()
    //        //      print("Return code: %d" % child.exitstatus)
    //
    //        ProcessBuilder builder = new ProcessBuilder(executeArgs);
    //        final Process process = builder.start();
    //        OutputStream stdin = process.getOutputStream();
    //        InputStream stdout = process.getInputStream();
    //
    //        BufferedReader reader = new BufferedReader(new InputStreamReader(stdout));
    //        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(stdin));
    //
    //        writer.write(getPayload());
    //        writer.flush();
    //        writer.close();
    //
    //        int exitValue = process.waitFor();
    //        System.out.printf("Program terminated with return code: %s%n", exitValue);
    //    }
}
