package org.owasp.benchmarkutils.score;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.apache.commons.io.IOUtils;

public class TestHelper {

    public static final String UFT_8 = StandardCharsets.UTF_8.name();

    public static ResultFile resultFileOf(String filename) {
        try {
            return new ResultFile(filename, contentOf(filename));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static String contentOf(String filename) {
        try {
            return IOUtils.toString(asStream(filename), UFT_8);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static InputStream asStream(String filename) {
        return Objects.requireNonNull(
                TestHelper.class.getClassLoader().getResourceAsStream(filename));
    }
}
