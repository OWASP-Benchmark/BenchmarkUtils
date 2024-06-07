package org.owasp.benchmarkutils.score.domain;

public class TestSuiteName {

    private final String name;

    public TestSuiteName(String name) {
        this.name = name;
    }

    public String simpleName() {
        return name;
    }

    /**
     * If required, provide a more descriptive test suite name than the base, single word test suite
     * name.
     */
    public String fullName() {
        if ("Benchmark".equals(name)) {
            return "OWASP Benchmark";
        }

        return simpleName();
    }
}
