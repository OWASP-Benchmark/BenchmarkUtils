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
 * @created 2024
 */
package org.owasp.benchmarkutils.score.report;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.owasp.benchmarkutils.score.report.Formats.fourDecimalPlacesNumber;
import static org.owasp.benchmarkutils.score.report.Formats.singleDecimalPlaceNumber;
import static org.owasp.benchmarkutils.score.report.Formats.twoDecimalPlacesPercentage;

import java.util.Locale;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class FormatsTest {

    private Locale originalLocale;

    @BeforeEach
    void saveLocale() {
        originalLocale = Locale.getDefault();
    }

    @AfterEach
    void restoreLocale() {
        Locale.setDefault(originalLocale);
    }

    @Test
    void hasFormatterForTwoDecimalPlacesPercentage() {
        assertEquals("1234.57%", twoDecimalPlacesPercentage.format(12.345678));
    }

    @Test
    void hasFormatterForFourDecimalPlaces() {
        assertEquals("12.3457", fourDecimalPlacesNumber.format(12.345678));
    }

    @Test
    void hasFormatterForSingleDecimalPlace() {
        assertEquals("12.3", singleDecimalPlaceNumber.format(12.345678));
    }

    @Test
    void formatsUseDotDecimalSeparatorRegardlessOfLocale() {
        Locale.setDefault(Locale.GERMANY);

        assertEquals(
                "1234.57%",
                twoDecimalPlacesPercentage.format(12.345678),
                "Percentage formatter must use dot separator even under German locale");
        assertEquals(
                "12.3",
                singleDecimalPlaceNumber.format(12.345678),
                "Single decimal formatter must use dot separator even under German locale");
        assertEquals(
                "12.3457",
                fourDecimalPlacesNumber.format(12.345678),
                "Four decimal formatter must use dot separator even under German locale");
    }
}
