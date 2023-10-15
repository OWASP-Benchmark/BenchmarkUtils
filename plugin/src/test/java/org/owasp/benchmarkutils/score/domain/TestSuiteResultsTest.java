package org.owasp.benchmarkutils.score.domain;

import static org.junit.jupiter.api.Assertions.*;
import static org.owasp.benchmarkutils.score.TestHelper.listOf;
import static org.owasp.benchmarkutils.score.TestHelper.setOf;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.util.Arrays;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.domain.exception.NoToolNameProvided;
import org.owasp.benchmarkutils.score.domain.exception.NoToolTypeProvided;

public class TestSuiteResultsTest {

    private static final String SEP = System.getProperty("line.separator");
    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    TestSuiteResults defaultResults;

    @BeforeEach
    void setUp() {
        System.setOut(new PrintStream(outContent));
        defaultResults = new TestSuiteResults("ToolName", true, ToolType.SAST);
    }

    @AfterEach
    public void restoreSystemOut() {
        System.setOut(originalOut);
    }

    @Test
    void rejectsMissingToolNameAtConstructor() {
        assertThrows(
                NoToolNameProvided.class, () -> new TestSuiteResults(null, true, ToolType.SAST));
    }

    @Test
    void rejectsEmptyToolName() {
        assertThrows(NoToolNameProvided.class, () -> new TestSuiteResults("", true, ToolType.SAST));
    }

    @Test
    void rejectsMissingToolType() {
        assertThrows(NoToolTypeProvided.class, () -> new TestSuiteResults("ToolName", true, null));
    }

    @Test
    void setsFieldsOnConstructor() {
        TestSuiteResults result = new TestSuiteResults("ToolName", true, ToolType.SAST);

        assertEquals("ToolName", result.getToolName());
        assertTrue(result.isCommercial());
        assertEquals(ToolType.SAST, result.getToolType());
    }

    @Test
    void updatesToolName() {
        defaultResults.setToolName("NewToolName");

        assertEquals("NewToolName", defaultResults.getToolName());
    }

    @Test
    void rejectsMissingToolNameAtSetter() {
        assertThrows(NoToolNameProvided.class, () -> defaultResults.setToolName(null));
    }

    @Test
    void hasDefaultTestSuiteVersion() {
        assertEquals("notSet", defaultResults.getTestSuiteVersion());
    }

    @Test
    void updatesTestSuiteVersion() {
        defaultResults.setTestSuiteVersion("1.2.3");

        assertEquals("1.2.3", defaultResults.getTestSuiteVersion());
    }

    @Test
    void hasDefaultTime() {
        assertEquals("Unknown", defaultResults.getTime());
    }

    @Test
    void updatesTime() {
        defaultResults.setTime("42");

        assertEquals("42", defaultResults.getTime());
    }

    @Test
    void hasNoDefaultToolVersion() {
        assertNull(defaultResults.getToolVersion());
    }

    @Test
    void updatesToolVersion() {
        defaultResults.setToolVersion("1.2.3");

        assertEquals("1.2.3", defaultResults.getToolVersion());
    }

    @Test
    void addsAndFindsTestCaseResults() {
        TestCaseResult firstResult = new TestCaseResult(1, CweNumber.XSS);
        TestCaseResult secondResult = new TestCaseResult(1, CweNumber.PATH_TRAVERSAL);
        TestCaseResult thirdResult = new TestCaseResult(2, CweNumber.XSS);

        defaultResults.add(firstResult);
        defaultResults.add(secondResult);
        defaultResults.add(thirdResult);

        assertEquals(listOf(firstResult, secondResult), defaultResults.resultsFor(1));
    }

    @Test
    void returnsTestNumbers() {
        defaultResults.add(new TestCaseResult(1, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(1, CweNumber.PATH_TRAVERSAL));
        defaultResults.add(new TestCaseResult(2, CweNumber.XSS));

        assertEquals(setOf(1, 2), defaultResults.testNumbers());
    }

    @Test
    void ignoresImpossibleTestNumbers() {
        defaultResults.add(new TestCaseResult(-1, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(0, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(10001, CweNumber.XSS));

        assertTrue(defaultResults.testNumbers().isEmpty());
    }

    @Test
    void warnsAboutIgnoredTestNumber() {
        defaultResults.add(new TestCaseResult(-1, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(0, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(1, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(10000, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(10001, CweNumber.XSS));

        String[] resultLines = outContent.toString().split(SEP);

        System.out.println(Arrays.toString(resultLines));

        assertEquals(3, resultLines.length);
        assertEquals("WARN: Ignoring test case result for test number -1", resultLines[0]);
        assertEquals("WARN: Ignoring test case result for test number 0", resultLines[1]);
        assertEquals("WARN: Ignoring test case result for test number 10001", resultLines[2]);
    }

    @Test
    void returnsAmountOfResults() {
        defaultResults.add(new TestCaseResult(1, CweNumber.XSS));
        defaultResults.add(new TestCaseResult(1, CweNumber.PATH_TRAVERSAL));
        defaultResults.add(new TestCaseResult(2, CweNumber.XSS));

        assertEquals(2, defaultResults.getTotalResults());
    }

    @ParameterizedTest
    @MethodSource(
            "org.owasp.benchmarkutils.score.domain.TestSuiteResultsTest#displayNameTestValues")
    void buildsDisplayName(
            String expectedName,
            boolean anonymous,
            String toolVersion,
            boolean anonymousMode,
            boolean commercial,
            String toolName) {
        TestSuiteResults results = new TestSuiteResults(toolName, commercial, ToolType.SAST);
        results.setToolVersion(toolVersion);

        if (anonymous) {
            results.setAnonymous();
        }

        assertEquals(expectedName, results.getDisplayName(anonymousMode));
    }

    private static Stream<Arguments> displayNameTestValues() {
        return Stream.of(
                Arguments.of("SAST-01", true, null, false, false, "ToolName"),
                Arguments.of("ToolName", false, null, false, false, "ToolName"),
                Arguments.of("ToolName", false, "", false, false, "ToolName"),
                Arguments.of("ToolName v1.2.3", false, "1.2.3", true, false, "ToolName"),
                Arguments.of("ToolName v1.2.3", false, "1.2.3", false, true, "ToolName"));
    }
}
