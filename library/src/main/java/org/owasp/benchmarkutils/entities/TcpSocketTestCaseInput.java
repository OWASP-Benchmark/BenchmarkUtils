package org.owasp.benchmarkutils.entities;

import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("TcpSocket")
public class TcpSocketTestCaseInput extends ExecutableTestCaseInput {

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
