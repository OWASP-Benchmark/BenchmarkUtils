package org.owasp.benchmarkutils.tools;

import java.io.PrintStream;

public class SimpleConsoleLogger implements Logger {
    private static Logger _instance;

    private PrintStream out;

    private SimpleConsoleLogger() {
        out = System.out;
    }

    public static Logger getLogger() {
        Logger simpleLogger = _instance;
        if (simpleLogger != null) {
            return simpleLogger;
        } else {
            _instance = new SimpleConsoleLogger();
            return _instance;
        }
    }

    @Override
    public void println(String message) {
        out.println(message);
    }

    @Override
    public void println() {
        out.println();
    }

    @Override
    public void printf(String format, Object... args) {
        out.printf(format, args);
    }
}
