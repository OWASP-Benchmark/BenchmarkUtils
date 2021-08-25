package org.owasp.benchmarkutils.tools;

public interface Logger {

    void println(String message);

    void println();

    void printf(String format, Object... args);
}
