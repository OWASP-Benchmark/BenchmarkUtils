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
 * @created 2023
 */
package org.owasp.benchmarkutils.score;

import static java.io.File.createTempFile;
import static java.util.UUID.randomUUID;
import static org.apache.commons.lang.math.RandomUtils.nextBoolean;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintStream;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.yaml.snakeyaml.DumperOptions;
import org.yaml.snakeyaml.Yaml;

public class ConfigurationTest {

    private Map<String, Object> defaultConfig;
    private Yaml yaml;
    private final ClassLoader classLoader = Configuration.class.getClassLoader();
    private ByteArrayOutputStream out;
    private static final String SEP = System.getProperty("line.separator");

    @BeforeEach
    public void setUp() {
        // Prevent JSON-like output (https://stackoverflow.com/a/62305688)
        final DumperOptions options = new DumperOptions();
        options.setDefaultFlowStyle(DumperOptions.FlowStyle.BLOCK);
        options.setPrettyFlow(true);

        yaml = new Yaml(options);
        defaultConfig = yaml.load(classLoader.getResourceAsStream(Configuration.DEFAULT_CONFIG));

        out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
    }

    @Test
    public void canReadConfigFromDefaultFile() {
        assertConfigEquals(defaultConfig, Configuration.fromDefaultConfig());
    }

    private void assertConfigEquals(
            Map<String, Object> expectedConfig, Configuration actualConfig) {
        assertEquals(expectedConfig.get("expectedresults"), actualConfig.expectedResultsFileName);
        assertEquals(expectedConfig.get("resultsfileordir"), actualConfig.resultsFileOrDirName);
        assertEquals(expectedConfig.get("focustool"), actualConfig.focus);
        assertEquals(expectedConfig.get("anonymousmode"), actualConfig.anonymousMode);
        assertEquals(expectedConfig.get("averageonlymode"), actualConfig.showAveOnlyMode);
        assertEquals(expectedConfig.get("mixedmode"), actualConfig.mixedMode);
        assertEquals(expectedConfig.get("cwecategoryname"), actualConfig.cweCategoryName);
        assertEquals(expectedConfig.get("tprlabel"), actualConfig.tprLabel);
        assertEquals(expectedConfig.get("includeprojectlink"), actualConfig.includeProjectLink);
        assertEquals(expectedConfig.get("includeprecision"), actualConfig.includePrecision);
    }

    @Test
    void informsAboutDefaultConfig() {
        Configuration.fromDefaultConfig();
        assertEquals(
                "INFO: Default YAML Scoring config file found and loaded." + SEP, out.toString());
    }

    @Test
    void canReadConfigFromFileByResource() {
        assertConfigEquals(
                defaultConfig, Configuration.fromResourceFile(Configuration.DEFAULT_CONFIG));
    }

    @Test
    void informsAboutResourceConfig() {
        Configuration.fromResourceFile(Configuration.DEFAULT_CONFIG);

        assertEquals("INFO: YAML Scoring config file found and loaded." + SEP, out.toString());
    }

    @Test
    void throwsExceptionIfResourceFileDoesNotExist() {
        Configuration.ConfigCouldNotBeParsed e =
                assertThrows(
                        Configuration.ConfigCouldNotBeParsed.class,
                        () -> Configuration.fromResourceFile("does-not-exist.yaml"),
                        "No exception was thrown");

        assertEquals(
                "YAML scoring configuration file: 'does-not-exist.yaml' not found on classpath!",
                e.getMessage());
    }

    @Test
    void canReadConfigFromFileByPath() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();

        testConfig.put("expectedresults", randomString());
        testConfig.put("resultsfileordir", randomString());
        testConfig.put("focustool", randomString());
        testConfig.put("anonymousmode", randomBoolean());
        testConfig.put("averageonlymode", randomBoolean());
        testConfig.put("mixedmode", randomBoolean());
        testConfig.put("cwecategoryname", randomString());
        testConfig.put("tprlabel", randomString());
        testConfig.put("includeprojectlink", randomBoolean());
        testConfig.put("includeprecision", randomBoolean());

        File tempConfigFile = createConfigFile(testConfig);

        assertConfigEquals(testConfig, Configuration.fromFile(tempConfigFile.getAbsolutePath()));
    }

    private File createConfigFile(Map<String, Object> testConfig) throws IOException {
        File tempConfigFile = createTempFile("config", ".yaml");

        try (FileWriter writer = new FileWriter(tempConfigFile)) {
            yaml.dump(testConfig, writer);
        }
        return tempConfigFile;
    }

    private String randomString() {
        return randomUUID().toString();
    }

    private Boolean randomBoolean() {
        return nextBoolean();
    }

    @Test
    void informsAboutFileConfig() throws Exception {
        Configuration.fromFile(provideEmptyConfig().getAbsolutePath());

        assertEquals("INFO: YAML Scoring config file found and loaded." + SEP, out.toString());
    }

    @Test
    void throwsExceptionIfFileDoesNotExist() {
        Configuration.ConfigCouldNotBeParsed e =
                assertThrows(
                        Configuration.ConfigCouldNotBeParsed.class,
                        () -> Configuration.fromFile("does-not-exist.yaml"),
                        "No exception was thrown");

        assertEquals(
                "YAML scoring configuration file: 'does-not-exist.yaml' not found!",
                e.getMessage());
    }

    @Test
    void mergesWithDefaultConfig() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();

        testConfig.put("expectedresults", randomString());
        testConfig.put("focustool", randomString());
        testConfig.put("averageonlymode", !((Boolean) defaultConfig.get("averageonlymode")));
        testConfig.put("cwecategoryname", randomString());
        testConfig.put("includeprojectlink", !((Boolean) defaultConfig.get("includeprojectlink")));

        Configuration actualConfig =
                Configuration.fromFile(createConfigFile(testConfig).getAbsolutePath());

        assertEquals(testConfig.get("expectedresults"), actualConfig.expectedResultsFileName);
        assertEquals(defaultConfig.get("resultsfileordir"), actualConfig.resultsFileOrDirName);
        assertEquals(testConfig.get("focustool"), actualConfig.focus);
        assertEquals(defaultConfig.get("anonymousmode"), actualConfig.anonymousMode);
        assertEquals(testConfig.get("averageonlymode"), actualConfig.showAveOnlyMode);
        assertEquals(defaultConfig.get("mixedmode"), actualConfig.mixedMode);
        assertEquals(testConfig.get("cwecategoryname"), actualConfig.cweCategoryName);
        assertEquals(defaultConfig.get("tprlabel"), actualConfig.tprLabel);
        assertEquals(testConfig.get("includeprojectlink"), actualConfig.includeProjectLink);
        assertEquals(defaultConfig.get("includeprecision"), actualConfig.includePrecision);
    }

    @Test
    void doesNotFailMergingOnAnyMissingField() throws IOException {
        assertConfigEquals(
                defaultConfig, Configuration.fromFile(provideEmptyConfig().getAbsolutePath()));
    }

    private File provideEmptyConfig() throws IOException {
        // Using config with dummy value (otherwise there'll be an exception)
        HashMap<String, Object> someConfig = new HashMap<>();
        someConfig.put("something", "value");

        return createConfigFile(someConfig);
    }

    @Test
    void usesDefaultValuesForHtmlReportStrings() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();

        testConfig.put("includeprojectlink", true);
        testConfig.put("includeprecision", true);

        Configuration config =
                Configuration.fromFile(createConfigFile(testConfig).getAbsolutePath());

        assertTrue(config.report.html.projectLinkEntry.contains("OWASP Benchmark Project Site"));
        assertTrue(config.report.html.precisionKeyEntry.contains("Precision = TP / ( TP + FP )"));
        assertTrue(
                config.report.html.fsCoreEntry.contains(
                        "F-score = 2 * Precision * Recall / (Precision + Recall)"));
    }

    @Test
    void usesDefaultValuesForHtmlReportStringsWithoutProjectLink() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();

        testConfig.put("includeprojectlink", false);
        testConfig.put("includeprecision", true);

        Configuration config =
                Configuration.fromFile(createConfigFile(testConfig).getAbsolutePath());

        assertTrue(config.report.html.projectLinkEntry.isEmpty());
        assertFalse(config.report.html.precisionKeyEntry.isEmpty());
        assertFalse(config.report.html.fsCoreEntry.isEmpty());
    }

    @Test
    void usesDefaultValuesForHtmlReportStringsWithoutPrecision() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();

        testConfig.put("includeprojectlink", true);
        testConfig.put("includeprecision", false);

        Configuration config =
                Configuration.fromFile(createConfigFile(testConfig).getAbsolutePath());

        assertFalse(config.report.html.projectLinkEntry.isEmpty());
        assertTrue(config.report.html.precisionKeyEntry.isEmpty());
        assertTrue(config.report.html.fsCoreEntry.isEmpty());
    }

    @Test
    void usesProvidedValuesForHtmlReportStrings() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();
        Map<String, Object> report = new HashMap<>();
        Map<String, Object> html = new HashMap<>();

        testConfig.put("includeprojectlink", true);
        testConfig.put("includeprecision", true);

        html.put("projectLinkEntry", "<p>projectLinkEntry</p>");
        html.put("precisionKeyEntry", "<p>precisionKeyEntry</p>");
        html.put("fsCoreEntry", "<p>fsCoreEntry</p>");

        report.put("html", html);
        testConfig.put("report", report);

        Configuration config =
                Configuration.fromFile(createConfigFile(testConfig).getAbsolutePath());

        assertEquals("<p>projectLinkEntry</p>", config.report.html.projectLinkEntry);
        assertEquals("<p>precisionKeyEntry</p>", config.report.html.precisionKeyEntry);
        assertEquals("<p>fsCoreEntry</p>", config.report.html.fsCoreEntry);
    }

    @Test
    void usesProvidedValuesForHtmlReportStringsWithoutProjectLink() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();
        Map<String, Object> report = new HashMap<>();
        Map<String, Object> html = new HashMap<>();

        testConfig.put("includeprojectlink", false);
        testConfig.put("includeprecision", true);

        html.put("projectLinkEntry", "<p>projectLinkEntry</p>");
        html.put("precisionKeyEntry", "<p>precisionKeyEntry</p>");
        html.put("fsCoreEntry", "<p>fsCoreEntry</p>");

        report.put("html", html);
        testConfig.put("report", report);

        Configuration config =
                Configuration.fromFile(createConfigFile(testConfig).getAbsolutePath());

        assertTrue(config.report.html.projectLinkEntry.isEmpty());
        assertEquals("<p>precisionKeyEntry</p>", config.report.html.precisionKeyEntry);
        assertEquals("<p>fsCoreEntry</p>", config.report.html.fsCoreEntry);
    }

    @Test
    void usesProvidedValuesForHtmlReportStringsWithoutPrecision() throws IOException {
        Map<String, Object> testConfig = new HashMap<>();
        Map<String, Object> report = new HashMap<>();
        Map<String, Object> html = new HashMap<>();

        testConfig.put("includeprojectlink", true);
        testConfig.put("includeprecision", false);

        html.put("projectLinkEntry", "<p>projectLinkEntry</p>");
        html.put("precisionKeyEntry", "<p>precisionKeyEntry</p>");
        html.put("fsCoreEntry", "<p>fsCoreEntry</p>");

        report.put("html", html);
        testConfig.put("report", report);

        Configuration config =
                Configuration.fromFile(createConfigFile(testConfig).getAbsolutePath());

        assertEquals("<p>projectLinkEntry</p>", config.report.html.projectLinkEntry);
        assertTrue(config.report.html.precisionKeyEntry.isEmpty());
        assertTrue(config.report.html.fsCoreEntry.isEmpty());
    }

    @Test
    void handlesMultiLineValuesInYaml() {
        Configuration config = Configuration.fromResourceFile("report-html-config.yml");

        assertEquals("<p>\n  projectLinkEntry\n</p>\n", config.report.html.projectLinkEntry);
        assertEquals("<p>\n  precisionKeyEntry\n</p>\n", config.report.html.precisionKeyEntry);
        assertEquals("<p>\n  fsCoreEntry\n</p>\n", config.report.html.fsCoreEntry);
    }
}
