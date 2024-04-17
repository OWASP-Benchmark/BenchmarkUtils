package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class SarifReaderTest {

    @ParameterizedTest(name = "{index} - extracts cwe number from input {0}")
    @ValueSource(
            strings = {
                "CWE-326",
                "CWE-326: Inadequate Encryption Strength",
                "external/cwe/cwe-326",
                "CWE:326"
            })
    void extractsCweNumberFromInput(String input) {
        assertEquals(326, SarifReader.extractCwe(input));
    }
}
