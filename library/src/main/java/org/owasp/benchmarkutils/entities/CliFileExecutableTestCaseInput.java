package org.owasp.benchmarkutils.entities;

import java.util.List;
import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlElement;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("CliFile")
public class CliFileExecutableTestCaseInput extends ExecutableTestCaseInput {

    List<RequestVariable> fileArgs;

    @XmlElement(name = "fileArg", required = true)
    @NotNull
    public List<RequestVariable> getFileArgs() {
        return fileArgs;
    }

    public CliRequest buildAttackRequest() {
        //		ArrayList<String> executeArgs = new ArrayList<>();
        //		// FIXME: This will break if the command string has arguments that contain spaces.
        //		executeArgs.addAll(Arrays.asList(getCommand().split(" ")));
        //		executeArgs.addAll(getArgs());

        setSafe(false);
        return new CliRequest(getCommand(), getFileArgs());
    }

    public CliRequest buildSafeRequest() {
        setSafe(true);
        return new CliRequest(getCommand(), getFileArgs());
    }

    public void setSafe(boolean isSafe) {
        //        this.isSafe = isSafe;
        for (RequestVariable arg : getFileArgs()) {
            // setSafe() considers whether attack and safe values exist for this parameter before
            // setting isSafe true or false. So you don't have to check that here.
            arg.setSafe(isSafe);
        }
    }

    //    public void execute() {
    //        List<String> executeArgs = Arrays.asList(getCommand());
    //
    //        File argsFile = new File(TEST_SUITE_DIR, "args_file.txt");
    //
    //        //      args_file = 'args_file.txt'
    //        //      with open(TEST_SUITE_DIR + args_file, 'w') as f:
    //        //          f.write(arg1)
    //        //      crawlArgs.extend([args_file])
    //        //      child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
    //        //      child.logfile = sys.stdout
    //        //      child.expect(pexpect.EOF)
    //        //      child.close()
    //        //      print("Return code: %d" % child.exitstatus)
    //
    //        executeArgs.add(getPayload());
    //        executeArgs.add("-f");
    //        executeArgs.add(argsFile.getPath());
    //        try (PrintWriter writer = new PrintWriter(new FileWriter(argsFile))) {
    //            writer.print(getPayload());
    //        }
    //
    //        ProcessBuilder builder = new ProcessBuilder(executeArgs);
    //        final Process process = builder.start();
    //        int exitValue = process.waitFor();
    //        System.out.printf("Program terminated with return code: %s%n", exitValue);
    //    }
}
