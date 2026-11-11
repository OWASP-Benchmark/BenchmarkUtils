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
 */
package org.owasp.benchmarkutils.tools;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.helpers.RequestVariable;

public class CommandLineTestCaseRequestTest {

    @Test
    void buildCommandWithNoArgs() {
        CommandLineTestCaseRequest req = new CommandLineTestCaseRequest();
        req.setCommand("python3");

        List<String> cmd = req.buildCommand(true);

        assertEquals(List.of("python3"), cmd);
    }

    @Test
    void buildCommandWithBaseArgs() {
        CommandLineTestCaseRequest req = new CommandLineTestCaseRequest();
        req.setCommand("python3");
        req.setCommandArgs("test001.py --verbose");

        List<String> cmd = req.buildCommand(true);

        assertEquals(List.of("python3", "test001.py", "--verbose"), cmd);
    }

    @Test
    void buildCommandWithFormParamsInSafeMode() {
        CommandLineTestCaseRequest req = new CommandLineTestCaseRequest();
        req.setCommand("python3");
        req.setCommandArgs("test001.py");

        RequestVariable param =
                new RequestVariable("input", "hello", "input", "' OR 1=1 --", "input", "hello");
        req.setFormParams(Arrays.asList(param));

        List<String> cmd = req.buildCommand(true);

        assertEquals(
                List.of("python3", "test001.py", "--input", "hello"),
                cmd,
                "Safe mode should use the safe value");
    }

    @Test
    void buildCommandWithFormParamsInAttackMode() {
        CommandLineTestCaseRequest req = new CommandLineTestCaseRequest();
        req.setCommand("python3");
        req.setCommandArgs("test001.py");

        RequestVariable param =
                new RequestVariable("input", "hello", "input", "' OR 1=1 --", "input", "hello");
        req.setFormParams(Arrays.asList(param));

        List<String> cmd = req.buildCommand(false);

        assertEquals(
                List.of("python3", "test001.py", "--input", "' OR 1=1 --"),
                cmd,
                "Attack mode should use the attack value");
    }

    @Test
    void buildCommandWithMultipleParams() {
        CommandLineTestCaseRequest req = new CommandLineTestCaseRequest();
        req.setCommand("app");

        RequestVariable p1 =
                new RequestVariable("user", "admin", "user", "root", "user", "admin");
        RequestVariable p2 =
                new RequestVariable("pass", "safe123", "pass", "' DROP TABLE--", "pass", "safe123");
        req.setFormParams(Arrays.asList(p1, p2));

        List<String> cmd = req.buildCommand(true);

        assertEquals(
                List.of("app", "--user", "admin", "--pass", "safe123"),
                cmd);
    }

    @Test
    void getLastBuiltCommandReturnsUnmodifiableList() {
        CommandLineTestCaseRequest req = new CommandLineTestCaseRequest();
        req.setCommand("echo");

        List<String> cmd = req.getLastBuiltCommand(true);

        try {
            cmd.add("injected");
            throw new AssertionError("List should be unmodifiable");
        } catch (UnsupportedOperationException expected) {
            // correct behavior
        }
    }
}
