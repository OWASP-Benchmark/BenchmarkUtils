package org.owasp.benchmarkutils.score;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class BenchmarkScoreTest {

    private static final String SEP = System.getProperty("line.separator");
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @BeforeEach
    public void setUpStreams() {
        System.setOut(new PrintStream(outContent));
    }

    @AfterEach
    public void restoreStreams() {
        System.setOut(originalOut);
    }

    @Test
    void usesDefaultConfigAndInformsAboutUsageOnNullArgs() {
        BenchmarkScore.loadConfigFromCommandLineArguments(null);

        expectDefaultConfigAndUsageMessage();
    }

    private void expectDefaultConfigAndUsageMessage() {
        String[] resultLines = outContent.toString().split(SEP);

        assertEquals(2, resultLines.length);
        assertEquals(BenchmarkScore.USAGE_MSG, resultLines[0]);
        assertEquals(Configuration.DEFAULT_SUCCESS_MESSAGE, resultLines[1]);
    }

    @Test
    void usesDefaultConfigAndInformsAboutUsageOnEmptyArgs() {
        BenchmarkScore.loadConfigFromCommandLineArguments(new String[0]);

        expectDefaultConfigAndUsageMessage();
    }

    @Test
    void usesDefaultConfigAndInformsAboutUsageOnSingleElementArgs() {
        BenchmarkScore.loadConfigFromCommandLineArguments(new String[] {"a"});

        expectDefaultConfigAndUsageMessage();
    }

    @Test
    void usesDefaultConfigAndInformsAboutUsageOnMultiElementsArgs() {
        BenchmarkScore.loadConfigFromCommandLineArguments(new String[] {"a", "b", "c"});

        expectDefaultConfigAndUsageMessage();
    }

    @Test
    void usesDefaultConfigAndInformsAboutUsageOnTwoElementsNullArgs() {
        BenchmarkScore.loadConfigFromCommandLineArguments(new String[] {null, null});

        expectDefaultConfigAndUsageMessage();
    }

    @Test
    void throwsExceptionAndInformsAboutUsageOnTwoElementsArrayFirstNull() {
        assertThrows(
                IllegalArgumentException.class,
                () -> BenchmarkScore.loadConfigFromCommandLineArguments(new String[] {"a", null}));

        expectUsageMessage();
    }

    private void expectUsageMessage() {
        String[] resultLines = outContent.toString().split(SEP);

        assertEquals(1, resultLines.length);
        assertEquals(BenchmarkScore.USAGE_MSG, resultLines[0]);
    }

    @Test
    void throwsExceptionAndInformsAboutUsageOnTwoElementsArraySecondNull() {
        assertThrows(
                IllegalArgumentException.class,
                () -> BenchmarkScore.loadConfigFromCommandLineArguments(new String[] {null, "b"}));

        expectUsageMessage();
    }
}
