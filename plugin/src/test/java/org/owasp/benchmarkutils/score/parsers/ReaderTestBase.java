package org.owasp.benchmarkutils.score.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Collectors;
import org.owasp.benchmarkutils.score.ResultFile;

public abstract class ReaderTestBase {

    void assertOnlyMatcherClassIs(ResultFile resultFile, Class<? extends Reader> c) {
        List<Reader> readers =
                Reader.allReaders().stream()
                        .filter(r -> r.canRead(resultFile))
                        .collect(Collectors.toList());

        assertEquals(1, readers.size());

        assertTrue(readers.get(0).getClass().isAssignableFrom(c));
    }
}
