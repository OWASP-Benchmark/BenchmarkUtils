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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Sascha Knoop
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.ResultFile;

public abstract class ReaderTestBase {

    // This list is used in the next test
    private static final List<Reader> THE_READERS = Reader.allReaders();

    @Test
    public void assertReaderIsInReaderAllReadersList() {
        boolean readerInList = false;
        String thisReaderName = this.getClass().getSimpleName(); // This gets ReaderNameTEST
        thisReaderName = thisReaderName.substring(0, thisReaderName.length() - "TEST".length());
        for (Reader reader : THE_READERS) {
            if (reader.getClass().getSimpleName().equals(thisReaderName)) {
                readerInList = true;
                break;
            }
        }
        assertTrue(
                readerInList,
                "Reader " + thisReaderName + " must be added to Reader.allReaders() list");
    }

    protected void assertOnlyMatcherClassIs(ResultFile resultFile, Class<? extends Reader> c) {
        List<Class<?>> readers =
                Reader.allReaders().stream()
                        .filter(r -> r.canRead(resultFile))
                        .map(Reader::getClass)
                        .collect(Collectors.toList());

        assertEquals(simpleNames(singletonList(c)), simpleNames(readers));

        assertTrue(readers.get(0).isAssignableFrom(c));
    }

    private List<String> simpleNames(List<Class<?>> classList) {
        return classList.stream().map(Class::getSimpleName).collect(Collectors.toList());
    }
}
