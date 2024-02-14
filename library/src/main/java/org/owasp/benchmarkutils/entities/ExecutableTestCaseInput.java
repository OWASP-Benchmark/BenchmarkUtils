package org.owasp.benchmarkutils.entities;

import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlElement;

public abstract class ExecutableTestCaseInput extends TestCaseInput {

    private String command;

    //    private String payload;

    @XmlElement(name = "command", required = true)
    @NotNull
    public String getCommand() {
        return command;
    }

    public void setCommand(String command) {
        this.command = command;
    }

    public abstract CliRequest buildAttackRequest();

    public abstract CliRequest buildSafeRequest();

    //    public String getPayload() {
    //        return payload;
    //    }
    //
    //    public void setPayload(String payload) {
    //        this.payload = payload;
    //    }

    //    public void execute() {
    //        // Execute the appropriate command string
    //        List<String> executeArgs = Arrays.asList(command);
    //        //    	if (isSingleApplication) {
    //        //    		executeArgs = Arrays.asList("benchmark-python.py", "-t", this.getName());
    //        //    	} else {
    //        //    		executeArgs = Arrays.asList("testcode/" + "JulietPyTest" + this.getName() +
    // ".py");
    //        //    	}
    //
    //        if (payloadType == PayloadType.CLI_ARG) {
    //            //          crawlArgs.extend([arg1])
    //            //          child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
    //            //          child.logfile = sys.stdout
    //            //          child.expect(pexpect.EOF)
    //            //          child.close()
    //            //          print("Return code: %d" % child.exitstatus)
    //
    //            executeArgs.add(payload);
    //            ProcessBuilder builder = new ProcessBuilder(executeArgs);
    //            final Process process = builder.start();
    //            int exitValue = process.waitFor();
    //            System.out.printf("Program terminated with return code: %s%n", exitValue);
    //
    //        } else if (payloadType == PayloadType.CLI_FILE) {
    //            //            args_file = 'args_file.txt'
    //            //            with open(TEST_SUITE_DIR + args_file, 'w') as f:
    //            //                f.write(arg1)
    //            //            crawlArgs.extend([args_file])
    //            //            child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
    //            //            child.logfile = sys.stdout
    //            //            child.expect(pexpect.EOF)
    //            //            child.close()
    //            //            print("Return code: %d" % child.exitstatus)
    //        } else if (payloadType == PayloadType.CLI_STDIN) {
    //            //            child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
    //            //            #child.interact()
    //            //            child.sendline(arg1)
    //            //            child.logfile = sys.stdout
    //            //            child.expect(pexpect.EOF)
    //            //            child.close()
    //            //            print("Return code: %d" % child.exitstatus)
    //        } else {
    //            // TODO: Throw an exception?
    //            System.out.printf("ERROR: Unrecognized payload type: %s%n", payloadType);
    //        }
    //    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "[" + "command=" + command + "]";
    }
}
