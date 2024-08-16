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
 * @author Sascha Knoop
 * @created 2022
 */
package org.owasp.benchmarkutils.score;

import static org.junit.jupiter.api.extension.ExtensionContext.Namespace.GLOBAL;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Objects;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.owasp.benchmarkutils.score.service.ExpectedResultsProvider;

/**
 * This class provides an initialization method to be run before any tests start, as well as some
 * static helper methods.
 *
 * <p>The initialization sets up an ExpectedResults file before any of the scoring tests are run, as
 * that is required to generate a scorecard.
 */
public class TestHelper implements BeforeAllCallback, ExtensionContext.Store.CloseableResource {

    private static boolean started = false;

    @Override
    public void beforeAll(ExtensionContext context) {
        if (!started) {
            started = true;

            // Custom initialization is here

            // Initialize Expected Results File to use during testing
            String EXPECTED_RESULTS_TESTFILENAME =
                    "src/test/resources/expectedresults-testfile.csv";
            try {
                File EXPECTED_RESULTS_FILE = new File(EXPECTED_RESULTS_TESTFILENAME);
                TestSuiteResults tr =
                        ExpectedResultsProvider.parse(new ResultFile(EXPECTED_RESULTS_FILE));
            } catch (FileNotFoundException e) {
                System.out.println(
                        "FATAL ERROR: Can't find expected results test file: "
                                + EXPECTED_RESULTS_TESTFILENAME);
                System.exit(-1);
            } catch (IOException e) {
                System.out.println(
                        "FATL ERROR: Reading contents of expected results test file: "
                                + EXPECTED_RESULTS_TESTFILENAME);
                e.printStackTrace();
                System.exit(-1);
            }

            // Don't know if registering this callback hook is needed, but doing it anyway.
            context.getRoot().getStore(GLOBAL).put("BenchmarkTestSetup", this);
        }
    }

    @Override
    public void close() {
        // Any after all tests logic goes here. None currently.
    }

    public static ResultFile resultFileOf(String filename) {
        try {
            return new ResultFile(filename, contentOf(filename));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] contentOf(String filename) {
        try {
            return IOUtils.toByteArray(asStream(filename));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static ResultFile resultFileWithoutLineBreaksOf(String filename) {
        try {
            return new ResultFile(filename, contentWithoutLineBreaksOf(filename));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String contentWithoutLineBreaksOf(String filename) {
        try {
            return IOUtils.toString(asStream(filename), Charset.defaultCharset())
                    .replace('\n', ' ');
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static InputStream asStream(String filename) {
        InputStream stream = TestHelper.class.getClassLoader().getResourceAsStream(filename);
        if (stream == null) {
            System.out.println("TEST ERROR: Test file: " + filename + " does not exist");
        }
        return Objects.requireNonNull(stream);
    }
}
