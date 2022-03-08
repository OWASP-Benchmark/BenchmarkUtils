package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.owasp.benchmarkutils.score.BenchmarkScore;

public class ReaderTest {

    @ParameterizedTest(name = "{index} {0}")
    @ValueSource(
            strings = {
                "BenchmarkTest00042",
                "/BenchmarkTest00042",
                "c:\\somepath\\BenchmarkTest00042",
                "c:/somepath/BenchmarkTest00042",
                "/somepath/BenchmarkTest00042",
                "http://somewhere/BenchmarkTest00042.html",
                "https://somewhere:8443/BenchmarkTest00042.html",
            })
    public void readsTestNumberFromPath(String path) {
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
        assertEquals(42, Reader.testNumber(path));
    }

    @Test
    public void returnsInvalidNumberForNonMatchingPrefix() {
        BenchmarkScore.TESTCASENAME = "SomethingElse";
        assertEquals(-1, Reader.testNumber("/somepath/BenchmarkTest00042"));
    }

    @Test
    public void returnsInvalidNumberForPathWithoutTestfile() {
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
        assertEquals(-1, Reader.testNumber("/somepath/someotherfile"));
    }

    @ParameterizedTest(name = "{index} {0}")
    @CsvSource(
            value = {
                "BenchmarkTest00042|BenchmarkTest00042",
                "/BenchmarkTest00042|BenchmarkTest00042",
                "c:\\somepath\\BenchmarkTest00042|BenchmarkTest00042",
                "c:/somepath/BenchmarkTest00042|BenchmarkTest00042",
                "/somepath/BenchmarkTest00042|BenchmarkTest00042",
                "http://somewhere/BenchmarkTest00042.html|BenchmarkTest00042.html",
                "http://somewhere/BenchmarkTest00042.html?foo=bar|BenchmarkTest00042.html",
                "https://somewhere:8443/BenchmarkTest00042.html|BenchmarkTest00042.html",
                "/something/else|else",
                "/something/else.html|else.html"
            },
            delimiter = '|')
    public void extractsFilenameFromPath(String input, String expected) {
        assertEquals(expected, Reader.extractFilename(input));
    }
}
