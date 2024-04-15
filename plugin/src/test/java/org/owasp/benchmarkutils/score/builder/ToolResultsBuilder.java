package org.owasp.benchmarkutils.score.builder;

import java.util.HashMap;
import java.util.Map;
import org.owasp.benchmarkutils.score.CategoryResults;
import org.owasp.benchmarkutils.score.ToolResults;

public class ToolResultsBuilder {

    private Map<String, CategoryResults> categoryResultsMap = new HashMap<>();

    private ToolResultsBuilder() {}

    public static ToolResultsBuilder builder() {
        return new ToolResultsBuilder();
    }

    public ToolResults build() {
        return null;
    }

    public ToolResultsBuilder setCategoryResults(Map<String, CategoryResults> categoryResultsMap) {
        this.categoryResultsMap = categoryResultsMap;

        return this;
    }

    public ToolResultsBuilder setCategoryResult(String key, CategoryResults value) {
        this.categoryResultsMap.put(key, value);

        return this;
    }
}
