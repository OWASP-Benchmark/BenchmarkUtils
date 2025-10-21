/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https:/owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Sascha Knoop
 * @created 2025
 */
package org.owasp.benchmarkutils.report.sonarqube.dto;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public class SonarQubeResult {

    public Paging paging;

    public List<Rule> rules;

    @JsonDeserialize(using = KeepAsJsonDeserializer.class)
    public List<String> issues;

    @JsonDeserialize(using = KeepAsJsonDeserializer.class)
    public List<String> hotspots;

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Paging {

        @JsonAlias("total")
        public int resultCount;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Rule {

        @JsonAlias("key")
        public String ruleId;
    }
}
