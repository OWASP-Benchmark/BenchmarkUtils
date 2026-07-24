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

import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlElement;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("Stdin")
public class StdinExecutableTestCaseInput extends ExecutableTestCaseInput {

    RequestVariable stdinData;

    @XmlElement(name = "stdinData", required = true)
    @NotNull
    public RequestVariable getStdinData() {
        return stdinData;
    }

    public void setStdinData(RequestVariable stdinData) {
        this.stdinData = stdinData;
    }

    public CliRequest buildAttackRequest() {
        //		ArrayList<String> executeArgs = new ArrayList<>();
        //		// FIXME: This will break if the command string has arguments that contain spaces.
        //		executeArgs.addAll(Arrays.asList(getCommand().split(" ")));
        //		executeArgs.addAll(getArgs());

        stdinData.setSafe(false);
        return new CliRequest(getCommand(), null, getStdinData());
    }

    public CliRequest buildSafeRequest() {
        setSafe(true);
        return new CliRequest(getCommand(), null, getStdinData());
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
