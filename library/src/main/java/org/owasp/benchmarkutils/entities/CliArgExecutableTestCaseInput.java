/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author David Anderson
 * @created 2024
 */
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
        // Copy the given list so setSafe() does not affect other CliArgExecutableTestCaseInput
        // objects.
        this.args = new ArrayList<>(args);
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
        ArrayList<RequestVariable> argsCopy = new ArrayList<>();
        for (RequestVariable arg : args) {
            RequestVariable argCopy = new RequestVariable(arg);
            argCopy.setSafe(false);
            argsCopy.add(argCopy);
        }
        return new CliRequest(getCommand(), argsCopy, null);
    }

    public CliRequest buildSafeRequest() {
        ArrayList<RequestVariable> argsCopy = new ArrayList<>();
        for (RequestVariable arg : args) {
            RequestVariable argCopy = new RequestVariable(arg);
            argCopy.setSafe(true);
            argsCopy.add(argCopy);
        }
        return new CliRequest(getCommand(), argsCopy, null);
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
