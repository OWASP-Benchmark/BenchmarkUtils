package org.owasp.benchmarkutils.score;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.ByteArrayOutputStream;
import java.util.HashSet;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class CweNumberTest {

    private static final int UNMAPPED_CWE_NUMBER = 99999;
    ByteArrayOutputStream out;

    @BeforeEach
    public void setUp() {
        out = new java.io.ByteArrayOutputStream();
        System.setOut(new java.io.PrintStream(out));
    }

    @Test
    public void returnDontCareForUnmappedCweNumber() {
        assertEquals(CweNumber.DONTCARE, CweNumber.lookup(UNMAPPED_CWE_NUMBER));
    }

    @Test
    public void looksUpValueByInteger() {
        assertEquals(CweNumber.PATH_TRAVERSAL, CweNumber.lookup(CweNumber.PATH_TRAVERSAL.number));
    }

    @Test
    public void looksUpValueByString() {
        assertEquals(
                CweNumber.PATH_TRAVERSAL, CweNumber.lookup("" + CweNumber.PATH_TRAVERSAL.number));
    }

    @Test
    public void warnsAboutUnmappedCweNumber() {
        CweNumber.lookup(UNMAPPED_CWE_NUMBER);
        assertEquals(
                "WARN: Requested unmapped CWE number " + UNMAPPED_CWE_NUMBER + ".\n",
                out.toString());
    }

    @Test
    public void doesNotWarnForMappedCweNumber() {
        CweNumber.lookup(CweNumber.PATH_TRAVERSAL.number);
        assertEquals("", out.toString());
    }

    @Test
    public void returnsDontCareForUnparsableNumber() {
        assertEquals(CweNumber.DONTCARE, CweNumber.lookup("unparsable"));
    }

    @Test
    public void showsErrorForUnparsableNumber() {
        CweNumber.lookup("unparsable");
        assertEquals("ERROR: Failed to parse CWE number 'unparsable'.\n", out.toString());
    }

    @Test
    public void doesNotContainSameNumberTwice() {
        CweNumber[] enumValues = CweNumber.class.getEnumConstants();
        Set<Integer> cweNumbers = new HashSet<>();

        for (CweNumber cweNumber : enumValues) {
            cweNumbers.add(cweNumber.number);
        }

        assertEquals(enumValues.length, cweNumbers.size());
    }
}
