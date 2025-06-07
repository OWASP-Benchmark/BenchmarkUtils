/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Sascha Knoop
 * @created 2022
 */
package org.owasp.benchmarkutils.score;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.util.Map;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;

/**
 * The values of these scorecard generation variables can be changed via scorecardconfig.yaml files.
 * These affect overall scorecard generation. These were the original command line params to
 * scorecard generation.
 */
public class Configuration {

    public static final String DEFAULT_CONFIG = "defaultscoringconfig.yaml";
    public static final String DEFAULT_SUCCESS_MESSAGE =
            "INFO: Default YAML Scoring config file found and loaded.";
    public static final String NON_DEFAULT_SUCCESS_MESSAGE =
            "INFO: YAML Scoring config file found and loaded.";

    public final String expectedResultsFileName;

    /** The name of the tool to 'focus' on, if any */
    public final String focus;

    /** Indicates that the names of Commercial tools should be anonymized */
    public final boolean anonymousMode;

    /**
     * This is used to indicate that results from multiple versions of a test suite are included in
     * these results. Each set in their own directory with their associated expectedresults file.
     */
    public final boolean mixedMode;

    /**
     * Indicates that the results of Commercial tools should be suppressed. Only show their
     * averages.
     */
    public final boolean showAveOnlyMode;

    public final String resultsFileOrDirName;

    // Default name for vuln categories menu in scorecards.
    public final String cweCategoryName;

    // Default label for True Positive Rate
    public final String tprLabel;

    /**
     * Indicates whether a link to the project should be included in generated pages. By default,
     * yes.
     */
    public final boolean includeProjectLink;

    /** Indicates whether Precision score should be included in generated tables. By default, no. */
    public final boolean includePrecision;

    public final Report report;

    private static final Yaml yaml = new Yaml(defaultLoaderOptions());

    private static LoaderOptions defaultLoaderOptions() {
        LoaderOptions loaderOptions = new LoaderOptions();

        loaderOptions.setAllowDuplicateKeys(true);
        loaderOptions.setWarnOnDuplicateKeys(false);

        return loaderOptions;
    }

    public static Configuration fromDefaultConfig() {
        return fromInputStream(resourceAsStream(DEFAULT_CONFIG), DEFAULT_SUCCESS_MESSAGE);
    }

    public static Configuration fromResourceFile(String resourceFile) {
        return fromInputStream(resourceAsStream(resourceFile), NON_DEFAULT_SUCCESS_MESSAGE);
    }

    private static InputStream resourceAsStream(String resourceFile) {
        InputStream resourceAsStream =
                Configuration.class.getClassLoader().getResourceAsStream(resourceFile);

        if (resourceAsStream == null) {
            throw new ConfigCouldNotBeParsed(
                    "YAML scoring configuration file: '"
                            + resourceFile
                            + "' not found on classpath!");
        }

        return resourceAsStream;
    }

    private static Configuration fromInputStream(InputStream stream, String successMessage) {
        SequenceInputStream sequenceInputStream =
                new SequenceInputStream(resourceAsStream(DEFAULT_CONFIG), stream);

        Configuration configuration = new Configuration(yaml.load(sequenceInputStream));

        System.out.println(successMessage);

        return configuration;
    }

    private Configuration(Map<String, Object> yamlConfig) {
        expectedResultsFileName = (String) yamlConfig.get("expectedresults");
        focus = (String) yamlConfig.get("focustool");
        anonymousMode = (Boolean) yamlConfig.get("anonymousmode");
        mixedMode = (Boolean) yamlConfig.get("mixedmode");
        showAveOnlyMode = (Boolean) yamlConfig.get("averageonlymode");
        resultsFileOrDirName = (String) yamlConfig.get("resultsfileordir");
        cweCategoryName = (String) yamlConfig.get("cwecategoryname");
        tprLabel = (String) yamlConfig.get("tprlabel");
        includeProjectLink = (Boolean) yamlConfig.get("includeprojectlink");
        includePrecision = (Boolean) yamlConfig.get("includeprecision");

        report = new Report(yamlConfig);
    }

    public static Configuration fromFile(String pathToFile) {
        try (FileInputStream fileInputStream = new FileInputStream(pathToFile)) {
            return fromInputStream(fileInputStream, NON_DEFAULT_SUCCESS_MESSAGE);
        } catch (IOException e) {
            throw new ConfigCouldNotBeParsed(
                    "YAML scoring configuration file: '" + pathToFile + "' not found!");
        }
    }

    public static class ConfigCouldNotBeParsed extends RuntimeException {
        public ConfigCouldNotBeParsed(String message) {
            super(message);
        }
    }

    private Object deepGet(Map<?, ?> input, String... path) {
        Map<?, ?> current = input;

        for (int i = 0; i < path.length - 1; i++) {
            current = (Map<?, ?>) current.get(path[i]);
        }

        return current.get(path[path.length - 1]);
    }

    private String getOrDefault(StringCallback sc, String defaultValue) {
        try {
            return sc.run();
        } catch (Throwable ignored) {
            return defaultValue;
        }
    }

    public class Report {

        public final Html html;

        public Report(Map<String, Object> yamlConfig) {
            this.html = new Html(yamlConfig);
        }

        public class Html {

            /** Link to project, is empty if includeProjectLink is false */
            public final String projectLinkEntry;

            /**
             * Key Entry for Precision, which is added to the Key for tables that include Precision.
             * Is empty if includePrecision is set to false via config
             */
            public final String precisionKeyEntry;

            /**
             * Key Entry for F-Score, which is added to the Key for tables that also include
             * Precision. Is empty if includePrecision is set to false via config
             */
            public final String fsCoreEntry;

            private static final String DEFAULT_PROJECT_LINK =
                    "            <p>\n"
                            + "                For more information, please visit the <a href=\"https://owasp.org/www-project-benchmark/\">OWASP Benchmark Project Site</a>.\n"
                            + "            </p>\n";

            private static final String DEFAULT_PRECISION_KEY =
                    "<tr>\n"
                            + "                    <th>Precision = TP / ( TP + FP )</th>\n"
                            + "                    <td>The percentage of reported vulnerabilities that are true positives. Defined at <a href=\"https://en.wikipedia.org/wiki/Precision_and_recall\">Wikipedia</a>.</td>\n"
                            + "                </tr>\n";

            private static final String DEFAULT_FS_CORE_ENTRY =
                    "<tr>\n"
                            + "                    <th>F-score = 2 * Precision * Recall / (Precision + Recall)</th>\n"
                            + "                    <td>The harmonic mean of the precision and recall. A value of 1.0 indicates perfect precision and recall. Defined at <a href=\"https://en.wikipedia.org/wiki/F-score\">Wikipedia</a>.</td>\n"
                            + "                </tr>\n";

            public Html(Map<String, Object> yamlConfig) {
                if ((Boolean) yamlConfig.get("includeprojectlink")) {
                    projectLinkEntry =
                            getOrDefault(
                                    () ->
                                            (String)
                                                    deepGet(
                                                            yamlConfig,
                                                            "report",
                                                            "html",
                                                            "projectLinkEntry"),
                                    DEFAULT_PROJECT_LINK);
                } else {
                    projectLinkEntry = "";
                }

                if ((Boolean) yamlConfig.get("includeprecision")) {
                    precisionKeyEntry =
                            getOrDefault(
                                    () ->
                                            (String)
                                                    deepGet(
                                                            yamlConfig,
                                                            "report",
                                                            "html",
                                                            "precisionKeyEntry"),
                                    DEFAULT_PRECISION_KEY);
                    fsCoreEntry =
                            getOrDefault(
                                    () ->
                                            (String)
                                                    deepGet(
                                                            yamlConfig,
                                                            "report",
                                                            "html",
                                                            "fsCoreEntry"),
                                    DEFAULT_FS_CORE_ENTRY);
                } else {
                    precisionKeyEntry = "";
                    fsCoreEntry = "";
                }
            }
        }
    }

    private interface StringCallback {
        String run();
    }
}
