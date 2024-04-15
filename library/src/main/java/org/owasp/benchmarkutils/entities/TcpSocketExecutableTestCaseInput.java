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

import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("TcpSocket")
public class TcpSocketExecutableTestCaseInput extends ExecutableTestCaseInput {

    public RequestVariable getTcpSocketData() {
        // FIXME
        return null;
    }

    public CliRequest buildAttackRequest() {
        //		ArrayList<String> executeArgs = new ArrayList<>();
        //		// FIXME: This will break if the command string has arguments that contain spaces.
        //		executeArgs.addAll(Arrays.asList(getCommand().split(" ")));
        //		executeArgs.addAll(getArgs());

        setSafe(false);
        return new CliRequest(getCommand(), null, getTcpSocketData());
    }

    public CliRequest buildSafeRequest() {
        setSafe(true);
        return new CliRequest(getCommand(), null, getTcpSocketData());
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
    //        // FIXME: Not yet implemented
    //
    //        // System.out.printf("Program terminated with return code: %s%n", exitValue);
    //    }
}
