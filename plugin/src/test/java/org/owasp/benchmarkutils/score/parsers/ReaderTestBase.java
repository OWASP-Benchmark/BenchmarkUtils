package org.owasp.benchmarkutils.score.parsers;

import static java.util.Collections.singletonList;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;
import org.owasp.benchmarkutils.score.ResultFile;

public abstract class ReaderTestBase {

    void assertOnlyMatcherClassIs(ResultFile resultFile, Class<? extends Reader> c) {
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
