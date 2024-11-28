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

import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.util.Locale;

public class Formats {

    private static final DecimalFormatSymbols locale = new DecimalFormatSymbols(Locale.US);

    public static final DecimalFormat twoDecimalPlacesPercentage = new DecimalFormat("#0.00%", locale);

    public static final DecimalFormat singleDecimalPlaceNumber = new DecimalFormat("0.0", locale);
    public static final DecimalFormat fourDecimalPlacesNumber = new DecimalFormat("#0.0000", locale);
}
