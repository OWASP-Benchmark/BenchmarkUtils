package org.owasp.benchmarkutils.score.domain;

// The types of tools that can generate results
public enum ToolType {
    SAST,
    DAST,
    IAST,
    Hybrid,
    Unknown
}
