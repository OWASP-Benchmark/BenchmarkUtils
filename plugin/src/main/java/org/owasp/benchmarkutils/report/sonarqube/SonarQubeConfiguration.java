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
 * @author Dave Wichers
 * @created 2025
 */
package org.owasp.benchmarkutils.report.sonarqube;

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
public class SonarQubeConfiguration {

    // DRW TODO: Test use of DEFAULT_CONFIG file with Docker version of SonarQube server from
    // runSonarQube.sh script
    // Loading of default yaml file likely not implemented yet.
    public static final String DEFAULT_CONFIG = "defaultsonarqubeconfig.yaml";
    public static final String DEFAULT_SUCCESS_MESSAGE =
            "INFO: Default SonarQube report config file found and loaded.";
    public static final String NON_DEFAULT_SUCCESS_MESSAGE =
            "INFO: Custom YAML SonarQube report config file found and loaded.";

    public String SONAR_USER = "admin";
    public String SONAR_PASSWORD = "P4ssword!!!!";
    public String SONAR_PROJECT = "benchmark";
    public String SONAR_HOST = "ubuntu-server";
    public Integer SONAR_PORT = 9876;
    public String TEST_SUITE_NAME = "Benchmark"; // Default value

    private static final Yaml yaml = new Yaml(defaultLoaderOptions());

    private static LoaderOptions defaultLoaderOptions() {
        LoaderOptions loaderOptions = new LoaderOptions();

        loaderOptions.setAllowDuplicateKeys(true);
        loaderOptions.setWarnOnDuplicateKeys(false);

        return loaderOptions;
    }

    public static SonarQubeConfiguration fromDefaultConfig() {
        return fromInputStream(resourceAsStream(DEFAULT_CONFIG), DEFAULT_SUCCESS_MESSAGE);
    }

    public static SonarQubeConfiguration fromResourceFile(String resourceFile) {
        return fromInputStream(resourceAsStream(resourceFile), NON_DEFAULT_SUCCESS_MESSAGE);
    }

    public static InputStream resourceAsStream(String resourceFile) {
        InputStream resourceAsStream =
                SonarQubeConfiguration.class.getClassLoader().getResourceAsStream(resourceFile);

        if (resourceAsStream == null) {
            throw new ConfigCouldNotBeParsed(
                    "YAML SonarQube configuration file: '"
                            + resourceFile
                            + "' not found on classpath!");
        }

        return resourceAsStream;
    }

    public static SonarQubeConfiguration fromInputStream(
            InputStream stream, String successMessage) {
        SequenceInputStream sequenceInputStream =
                new SequenceInputStream(resourceAsStream(DEFAULT_CONFIG), stream);

        SonarQubeConfiguration configuration = null;
        try {
            configuration = new SonarQubeConfiguration(yaml.load(sequenceInputStream));

        } catch (org.yaml.snakeyaml.scanner.ScannerException e) {
            System.out.println("FATAL ERROR: SonarQube YAML configuration file format error.");
            e.printStackTrace();
            System.exit(-1);
        }

        System.out.println(successMessage);
        return configuration;
    }

    private SonarQubeConfiguration(Map<String, Object> yamlConfig) {

        SONAR_USER = (String) yamlConfig.get("sonaruser");
        SONAR_PASSWORD = (String) yamlConfig.get("sonarpassword");
        SONAR_PROJECT = (String) yamlConfig.get("sonarproject");
        SONAR_HOST = (String) yamlConfig.get("sonarhost");
        SONAR_PORT = (Integer) yamlConfig.get("sonarport");
        // Optionally, the config file can specific the name of the test suite being scored
        if (yamlConfig.containsKey("testsuitename"))
            TEST_SUITE_NAME = (String) yamlConfig.get("testsuitename");
    }

    public static SonarQubeConfiguration fromFile(String pathToFile) {
        try (FileInputStream fileInputStream = new FileInputStream(pathToFile)) {
            return fromInputStream(fileInputStream, NON_DEFAULT_SUCCESS_MESSAGE);
        } catch (IOException e) {
            throw new ConfigCouldNotBeParsed(
                    "SonarQube YAML configuration file: '" + pathToFile + "' not found!");
        }
    }

    public static class ConfigCouldNotBeParsed extends RuntimeException {
        public ConfigCouldNotBeParsed(String message) {
            super(message);
        }
    }
}
