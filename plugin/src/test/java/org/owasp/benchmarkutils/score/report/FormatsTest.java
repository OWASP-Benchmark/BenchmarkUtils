package org.owasp.benchmarkutils.score.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.owasp.benchmarkutils.score.report.Formats.fourDecimalPlacesNumber;
import static org.owasp.benchmarkutils.score.report.Formats.twoDecimalPlacesPercentage;

import org.junit.jupiter.api.Test;

class FormatsTest {

    @Test
    void hasFormatterForTwoDecimalPlacesPercentage() {
        assertEquals("1234.57%", twoDecimalPlacesPercentage.format(12.345678));
    }

    @Test
    void hasFormatterForFourDecimalPlaces() {
        assertEquals("12.3457", fourDecimalPlacesNumber.format(12.345678));
    }
}
