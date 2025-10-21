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
package org.owasp.benchmarkutils.report.sonarqube;

import static java.lang.String.join;
import static java.nio.charset.Charset.defaultCharset;
import static org.apache.commons.io.FileUtils.writeStringToFile;
import static org.apache.commons.io.IOUtils.readLines;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.owasp.benchmarkutils.report.sonarqube.dto.SonarQubeResult;
import org.w3c.dom.Document;

@Mojo(
        name = "get-sonarqube-results",
        requiresProject = false,
        defaultPhase = LifecyclePhase.COMPILE)
public class SonarReport extends AbstractMojo {

    @Parameter(property = "configFile")
    String sonarqubeConfigFile;

    @Parameter(property = "projectNameSuffix")
    String projectNameSuffix = "";

    static final String USAGE_MSG =
            "Usage: -cf /PATH/TO/sonarqubeconfigfile.yaml or -cr sonarqubeconfigfile.yaml (where file is a resource)\n"
                    + "  optional: -projectSuffix VALUE (e.g., CWE114)";

    private static final int PAGE_SIZE = 500;

    // Initialized in loadConfigFromCommandLineArguments()
    private static String sonarAuth;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static SonarQubeConfiguration config;
    // Optional param, used when a scan of the whole project is too big, so it has to be broken into
    // pieces
    // Common solution is to scan by folder name, e.g., CWE114
    public static String projectSuffix;

    public static void main(String[] args) {

        try {
            loadConfigFromCommandLineArguments(args);
        } catch (RuntimeException e) {
            System.out.println(
                    "Error processing SonarQube Report download configuration. Aborting.");
            e.printStackTrace();
            System.exit(-1);
        }

        try {
            // Append default project name with suffix (if any) to compute actual SonarQube project
            // name
            String sonarQubeProjectName = config.SONAR_PROJECT + projectSuffix;
            String allJavaRules = String.join(",", allJavaRules());
            List<String> issues = new ArrayList<>();
            List<String> hotspots = new ArrayList<>();

            forAllPagesAt(
                    "issues/search?components="
                            + sonarQubeProjectName
                            + "&types=VULNERABILITY&&rules="
                            + allJavaRules,
                    (result -> issues.addAll(result.issues)));
            forAllPagesAt(
                    "hotspots/search?project=" + sonarQubeProjectName,
                    (result -> hotspots.addAll(result.hotspots)));

            writeStringToFile(
                    new File(
                            "results/"
                                    + resultFilename(config.TEST_SUITE_NAME, projectSuffix)
                                    + ".json"),
                    formattedJson(issues, hotspots),
                    defaultCharset());
        } catch (Exception e) {
            System.out.println("Error extracting SonarQube results from SonarQube server.");
            e.printStackTrace();
            System.exit(-1);
        }
    }

    /**
     * Process the command line arguments that make any configuration changes.
     *
     * @param args - args passed to main().
     */
    @VisibleForTesting
    static void loadConfigFromCommandLineArguments(String[] args) {
        if (args == null || (args.length != 2 && args.length != 4)) {
            System.out.println(USAGE_MSG);
            config = SonarQubeConfiguration.fromDefaultConfig();
        } else {
            // -cf indicates use the specified configuration file to config SonarQube params
            if ("-cf".equalsIgnoreCase(args[0])) {
                config = SonarQubeConfiguration.fromFile(args[1]);
                processResultsFilenameSuffixParam(2, args);
                // TODO: test CR option. Don't think it works yet.
            } else if ("-cr".equalsIgnoreCase(args[0])) {
                // -cr indicates use the specified configuration file resource to config SonarQube
                // params
                config = SonarQubeConfiguration.fromResourceFile(args[1]);
                processResultsFilenameSuffixParam(2, args);
            } else if (args[0] == null && args[1] == null) {
                System.out.println(USAGE_MSG);
                config = SonarQubeConfiguration.fromDefaultConfig();
            } else if ("-projectSuffix".equalsIgnoreCase(args[0])) {
                processResultsFilenameSuffixParam(0, args);
            } else {
                System.out.println(USAGE_MSG);
                throw new IllegalArgumentException();
            }
        }
        sonarAuth =
                Base64.getEncoder()
                        .encodeToString(
                                (config.SONAR_USER + ":" + config.SONAR_PASSWORD).getBytes());
    }

    /**
     * Check to see if the param at the specified index is 'projectSuffix'. If so, set the static
     * class variable projectSuffix to be "-" plus the value of that parameter.
     *
     * @param paramIndex The index into args to look for the 'projectSuffic' parameter.
     * @param args The args[] passed to main().
     */
    public static void processResultsFilenameSuffixParam(int paramIndex, String[] args) {
        if (args.length > paramIndex && "-projectSuffix".equals(args[paramIndex])) {
            SonarReport.projectSuffix = "-" + args[paramIndex + 1];
        }
    }

    @Override
    public void execute() {
        // The Maven plugin invocation of this can have configFile be null, so we check for that
        // specifically
        if (null == sonarqubeConfigFile) {
            String[] emptyMainArgs = {};
            main(emptyMainArgs); // Invoke SonarQube report extractions with no params
        } else {
            if (null == projectNameSuffix) {
                String[] mainArgs = {"-cf", sonarqubeConfigFile};
                main(mainArgs);
            } else {
                String[] mainArgs = {
                    "-cf", sonarqubeConfigFile, "-projectSuffix", projectNameSuffix
                };
                main(mainArgs);
            }
        }
        // TODO: Add support for using resource file, if CF is NOT specified
    }

    private static String resultFilename(String testSuiteName, String projectNameSuffix)
            throws Exception {

        return testSuiteName
                + projectNameSuffix
                + benchmarkVersion()
                + "-SonarQube-v"
                + apiCall("server/version");
    }

    /**
     * If scoring Java version of OWASP Benchmark, get the version from its pom file. If not, return
     * a blank string.
     *
     * @return Benchmark version number with '-' prepended or blank string.
     * @throws Exception
     */
    private static String benchmarkVersion() throws Exception {
        File pomfile = new File("pom.xml");
        if (pomfile.exists()) {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(pomfile);
            String project = doc.getElementsByTagName("artifactId").item(0).getTextContent();
            if ("benchmark".equals(project)) {
                return "-" + doc.getElementsByTagName("version").item(0).getTextContent();
            }
        }
        // If no pom file, or the project isn't OWASP Benchmark for Java, fall thru
        return "";
    }

    private static Set<String> allJavaRules() throws IOException {
        Set<String> javaRuleIds = new HashSet<>();

        forAllPagesAt(
                "rules/search",
                (result) ->
                        result.rules.stream()
                                .filter(rule -> rule.ruleId.startsWith("java:"))
                                .forEach(rule -> javaRuleIds.add(rule.ruleId)));

        return javaRuleIds;
    }

    private static void forAllPagesAt(String apiPath, Consumer<SonarQubeResult> pageHandlerCallback)
            throws IOException {
        int pages;
        int page = 1;

        do {
            SonarQubeResult result =
                    objectMapper.readValue(
                            apiCall(apiPath + pagingSuffix(page, apiPath)), SonarQubeResult.class);

            pages = (result.paging.resultCount / PAGE_SIZE) + 1;

            pageHandlerCallback.accept(result);

            page++;
            if (page * PAGE_SIZE > 10000) {
                System.err.println(
                        "Can't retrieve more than 10,000 SonarQube results for a single search, so not attempting to download any more.");
                break;
            }
        } while ((page - 1) < pages);
    }

    private static String pagingSuffix(int page, String apiPath) {
        return (apiPath.contains("?") ? "&" : "?") + "p=" + page + "&ps=" + PAGE_SIZE;
    }

    private static String apiCall(String apiPath) throws IOException {
        URL url =
                new URL(
                        "http://"
                                + config.SONAR_HOST
                                + ":"
                                + config.SONAR_PORT
                                + "/api/"
                                + apiPath);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setDoOutput(true);
        connection.setRequestProperty("Authorization", "Basic " + sonarAuth);

        String result = join("\n", readLines(connection.getInputStream(), defaultCharset()));
        return result;
    }

    private static String formattedJson(List<String> issues, List<String> hotspots)
            throws JsonProcessingException {
        String sb =
                "{\"issues\":["
                        + join(",", issues)
                        + "],\"hotspots\":["
                        + join(",", hotspots)
                        + "]}";

        return objectMapper
                .writerWithDefaultPrettyPrinter()
                .writeValueAsString(objectMapper.readValue(sb, Object.class));
    }
}
