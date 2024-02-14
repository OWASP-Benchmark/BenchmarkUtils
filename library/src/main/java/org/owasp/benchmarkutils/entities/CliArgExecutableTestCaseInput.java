package org.owasp.benchmarkutils.entities;

import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.NotNull;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("CliArg")
// @XmlType(name = "CliArgExecutableTestCaseInput")
public class CliArgExecutableTestCaseInput extends ExecutableTestCaseInput {

    List<RequestVariable> args;

    void beforeMarshal(Marshaller marshaller) {
        //        System.out.println("Before marshal");
        if (args != null && args.isEmpty()) args = null;
    }

    void afterUnmarshal(Unmarshaller unmarshaller, Object parent) {
        //        System.out.println("After unmarshal");
        if (args == null) args = new ArrayList<RequestVariable>();
    }

    @XmlElementWrapper(name = "args")
    @XmlElement(name = "arg", required = true)
    @NotNull
    public List<RequestVariable> getArgs() {
        return args;
    }

    public void setArgs(List<RequestVariable> args) {
        this.args = args;
    }

    public void addArg(RequestVariable arg) {
        if (this.args == null) {
            this.args = new ArrayList<>();
        }
        this.args.add(arg);
    }

    public CliRequest buildAttackRequest() {
        //		ArrayList<String> executeArgs = new ArrayList<>();
        //		// FIXME: This will break if the command string has arguments that contain spaces.
        //		executeArgs.addAll(Arrays.asList(getCommand().split(" ")));
        //		executeArgs.addAll(getArgs());

        setSafe(false);
        return new CliRequest(getCommand(), getArgs());
    }

    public CliRequest buildSafeRequest() {
        setSafe(true);
        return new CliRequest(getCommand(), getArgs());
    }

    public void setSafe(boolean isSafe) {
        //        this.isSafe = isSafe;
        for (RequestVariable arg : getArgs()) {
            // setSafe() considers whether attack and safe values exist for this parameter before
            // setting isSafe true or false. So you don't have to check that here.
            arg.setSafe(isSafe);
        }
    }

    //    @Override
    //    public String toString() {
    //        return this.getClass().getSimpleName() + " [args=" + getArgs() + "]";
    //    }
    @Override
    public String toString() {
        return this.getClass().getSimpleName()
                + "["
                + "command="
                + getCommand()
                + ", args="
                + getArgs()
                + "]";
    }

    //    public void execute() {
    //        List<String> executeArgs = Arrays.asList(getCommand());
    //
    //        //          crawlArgs.extend([arg1])
    //        //          child = pexpect.spawn("python", cwd=TEST_SUITE_DIR, args=crawlArgs)
    //        //          child.logfile = sys.stdout
    //        //          child.expect(pexpect.EOF)
    //        //          child.close()
    //        //          print("Return code: %d" % child.exitstatus)
    //
    //        executeArgs.add(getPayload());
    //        ProcessBuilder builder = new ProcessBuilder(executeArgs);
    //        final Process process = builder.start();
    //        int exitValue = process.waitFor();
    //        System.out.printf("Program terminated with return code: %s%n", exitValue);
    //    }

}
