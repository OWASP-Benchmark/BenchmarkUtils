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
 * @created 2015
 */
package org.owasp.benchmarkutils.score;

import com.google.common.annotations.VisibleForTesting;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.TreeSet;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.Category;
import org.owasp.benchmarkutils.helpers.CategoryGroup;
import org.owasp.benchmarkutils.helpers.CategoryGroups;
import org.owasp.benchmarkutils.helpers.Utils;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;
import org.owasp.benchmarkutils.score.parsers.Reader;
import org.owasp.benchmarkutils.score.report.ScatterHome;
import org.owasp.benchmarkutils.score.report.ScatterInterpretation;
import org.owasp.benchmarkutils.score.report.ScatterVulns;
import org.owasp.benchmarkutils.score.report.html.CommercialAveragesTable;
import org.owasp.benchmarkutils.score.report.html.HtmlStringBuilder;
import org.owasp.benchmarkutils.score.report.html.MenuUpdater;
import org.owasp.benchmarkutils.score.report.html.OverallStatsTable;
import org.owasp.benchmarkutils.score.report.html.ToolScorecard;
import org.owasp.benchmarkutils.score.report.html.VulnerabilityStatsTable;
import org.owasp.benchmarkutils.score.service.CountsPerCWE;
import org.owasp.benchmarkutils.score.service.ExpectedResultsProvider;
import org.owasp.benchmarkutils.score.service.ResultsFileCreator;

@Mojo(name = "create-scorecard", requiresProject = false, defaultPhase = LifecyclePhase.COMPILE)
public class BenchmarkScore extends AbstractMojo {

    @Parameter(property = "configFile")
    String scoringConfigFile;

    static final String USAGE_MSG =
            "Usage: -cf /PATH/TO/scoringconfigfile.yaml or -cr scoringconfigfile.yaml (where file is a resource)";

    // The 1st line of a supplied expectedresults.csv file looks like:
    // # test name, category, real vulnerability, cwe, TESTSUITENAME version: x.y, YYYY-MM-DD

    // Prefixes for generated test suites and file names. Used by lots of other classes for
    // scorecard generation.
    public static String TESTSUITEVERSION; // Pulled from expected results file
    public static TestSuiteName TESTSUITENAME; // Pulled from expected results file
    public static final String TEST = "Test";
    public static String TESTCASENAME; // Set w/TESTSUITE. i.e., TESTSUITE + TEST;

    public static String TESTPACKAGE = "org.owasp.benchmark.testcode.";

    // The # of numbers in a test case name. Must match what is actually generated.
    public static final int TESTIDLENGTH = 5;

    private static final String GUIDEFILENAME = "Scorecard_Guide.html";
    private static final String HOMEFILENAME = "Scorecard_Home.html";
    // scorecard dir normally created under current user directory
    public static final String SCORECARDDIRNAME = "scorecard";

    /*
     * The set of all the Tools. Each Tool includes the results for that tool.
     */
    private static Set<Tool> tools = new TreeSet<Tool>();

    // These Average Category values are computed as a side effect of running
    // generateVulnerabilityScorecards().
    private static Map<String, CategoryMetrics> averageCommercialToolMetrics = null;
    private static Map<String, CategoryMetrics> averageNonCommerciaToolMetrics = null;
    private static Map<String, CategoryMetrics> overallAveToolMetrics = null;

    public static Configuration config;

    /**
     * Process the command line arguments that make any configuration changes.
     *
     * @param args - args passed to main().
     */
    @VisibleForTesting
    static void loadConfigFromCommandLineArguments(String[] args) {
        if (args == null || args.length != 2) {
            System.out.println(USAGE_MSG);
            config = Configuration.fromDefaultConfig();
        } else {
            // -cf indicates use the specified configuration file to config Permute params
            if ("-cf".equalsIgnoreCase(args[0])) {
                config = Configuration.fromFile(args[1]);
            } else if ("-cr".equalsIgnoreCase(args[0])) {
                // -cr indicates use the specified configuration file resource to config Permute
                config = Configuration.fromResourceFile(args[1]);
            } else if (args[0] == null && args[1] == null) {
                System.out.println(USAGE_MSG);
                config = Configuration.fromDefaultConfig();
            } else {
                // pom settings for crawler forces creation of 2 args, but if none are provided,
                // they are null
                System.out.println(USAGE_MSG);
                throw new IllegalArgumentException();
            }
        }
    }

    @Override
    public void execute() {
        // The Maven plugin invocation of this can have configFile be null, so we check for that
        // specifically
        if (null == scoringConfigFile) {
            String[] emptyMainArgs = {};
            main(emptyMainArgs); // Invoke scorecard generation with no params
        } else {
            String[] mainArgs = {"-cf", scoringConfigFile};
            main(mainArgs);
        }
    }

    /**
     * This is the original main() method used to invoke the scorecard generator. e.g., mvn validate
     * -Pscorecard -Dexec.args="-cf ../TESTSUITENAME/config/testsuitescoringconfig.yaml"
     *
     * @param args - The command line arguments.
     */
    public static void main(String[] args) {
        try {
            loadConfigFromCommandLineArguments(args);
        } catch (RuntimeException e) {
            System.out.println("Error processing configuration for Scoring. Aborting.");
            e.printStackTrace();
            System.exit(-1);
        }

        // Step 0: Make sure the results file or directory exists before doing anything.
        File resultsFileOrDir = new File(config.resultsFileOrDirName);
        if (!resultsFileOrDir.exists()) {
            System.out.println(
                    "Error! - results file or directory: '"
                            + resultsFileOrDir.getAbsolutePath()
                            + "' doesn't exist.");
            System.exit(-1);
        }

        // Prepare the scorecard results directory for the newly generated scorecards
        // This directory is put in the same directory the results/ directory is located.

        // Step 1: Create the dir if it doesn't exist, or delete everything in it if it does
        File scoreCardDir = new File(resultsFileOrDir.getParent(), SCORECARDDIRNAME);
        try {
            if (!scoreCardDir.exists()) {
                scoreCardDir.mkdir();
            } else {
                System.out.println(
                        "Deleting previously generated scorecard files in: "
                                + scoreCardDir.getAbsolutePath());
                FileUtils.cleanDirectory(scoreCardDir);
            }

            // Step 2: Now copy the entire /content directory, that either didn't exist, or was just
            // deleted with everything else
            File contentDir = new File(scoreCardDir, "content");
            Utils.copyFilesFromDirRecursively("scorecard/content", contentDir.toPath());

        } catch (IOException | NullPointerException | IllegalArgumentException e) {
            System.out.println(
                    "Error dealing with scorecard directory: '"
                            + scoreCardDir.getAbsolutePath()
                            + "' for some reason!");
            e.printStackTrace();
            System.exit(-1);
        }

        // Step 3: Copy over the Homepage and Guide templates
        Path homeFilePath = null; // Save value for use in a later step
        try {
            homeFilePath = new File(scoreCardDir, HOMEFILENAME).toPath();
            Utils.copyFilesFromDirRecursively("scorecard/" + HOMEFILENAME, scoreCardDir.toPath());
            Utils.copyFilesFromDirRecursively("scorecard/" + GUIDEFILENAME, scoreCardDir.toPath());
        } catch (Exception e) {
            System.out.println("Problem copying home and guide files");
            e.printStackTrace();
        }

        // Steps 4 & 5: Read the expected results so we know what each tool 'should do' and each
        // tool's results file. a) is for 'mixed' mode, and b) is for normal mode
        try {
            // Mixed mode allows us to produce results for multiple versions of Benchmark in a
            // single scorecard. This was used years ago when versions of Benchmark were
            // changing more rapidly but hasn't been used in years.
            if (config.mixedMode) {

                if (!resultsFileOrDir.isDirectory()) {
                    System.out.println(
                            "Error! - results parameter is a file: '"
                                    + resultsFileOrDir.getAbsolutePath()
                                    + "' but must be a directory when processing results in 'mixed' mode.");
                    System.exit(-1);
                }

                // Go through each file in the root directory.
                // -- 1st find each directory. And then within each of those directories:
                //    -- 1st find the expected results file in that directory
                //    -- and then each of the actual results files in that directory

                for (File rootDirFile : resultsFileOrDir.listFiles()) {

                    if (rootDirFile.isDirectory()) {
                        // Process this directory
                        TestSuiteResults expectedResults = null;
                        String expectedResultsFilename = null;

                        // Step 4a: Find and process the expected results file so we know what each
                        // tool in this directory 'should do'
                        for (File resultsDirFile : rootDirFile.listFiles()) {

                            if (resultsDirFile.getName().startsWith("expectedresults-")) {
                                if (expectedResults != null) {
                                    System.out.println(
                                            "Found 2nd expected results file "
                                                    + resultsDirFile.getAbsolutePath()
                                                    + " in same directory. Can only have 1 in each results directory");
                                    System.exit(-1);
                                }

                                // read in the expected results for this directory of results
                                expectedResults = readExpectedResults(resultsDirFile);
                                if (expectedResults == null) {
                                    System.out.println(
                                            "Couldn't read expected results file: "
                                                    + resultsDirFile.getAbsolutePath());
                                    System.exit(-1);
                                }

                                expectedResultsFilename = resultsDirFile.getName();
                                // The else clause supports the ability to score mixed results
                                // across multiple versions of the same test suite.
                                if (TESTSUITEVERSION == null) {
                                    TESTSUITEVERSION = expectedResults.getTestSuiteVersion();
                                } else {
                                    // Hack to sort the test suite versions so earlier versions are
                                    // listed first. Won't always work for 3+ versions in the same
                                    // scorecard
                                    String newVersion = expectedResults.getTestSuiteVersion();

                                    TESTSUITEVERSION =
                                            TESTSUITEVERSION.compareTo(newVersion) < 0
                                                    ? TESTSUITEVERSION + "," + newVersion
                                                    : newVersion + "," + TESTSUITEVERSION;
                                }
                                System.out.println(
                                        "\nFound expected results file: "
                                                + resultsDirFile.getAbsolutePath());
                            } // end if
                        } // end for loop going thru each dir looking for expected results file

                        // Make sure we found an expected results file, before processing results
                        if (expectedResults == null) {
                            System.out.println(
                                    "Couldn't find expected results file in results directory: "
                                            + rootDirFile.getAbsolutePath());
                            System.out.println(
                                    "Expected results file has to be a .csv file that starts with: 'expectedresults-'");
                            System.exit(-1);
                        }

                        ResultsFileCreator resultsFileCreator =
                                new ResultsFileCreator(scoreCardDir, TESTSUITENAME);

                        // Step 5a: Go through each result file, score the tool, and generate a
                        // scorecard for that tool
                        if (!config.anonymousMode) {

                            for (File actual : rootDirFile.listFiles()) {
                                // Don't confuse the expected results file as an actual results file
                                // if its in the same directory
                                if (!actual.isDirectory()
                                        && !expectedResultsFilename.equals(actual.getName())) {
                                    // process() populates tools with the supplied tool's results
                                    process(actual, expectedResults, tools, resultsFileCreator);
                                }
                            }
                        } else {
                            // To handle anonymous mode, we are going to randomly grab files out of
                            // this directory and process them. By doing it this way, multiple runs
                            // should randomly order the commercial tools each time.
                            List<File> files = new ArrayList<File>();
                            for (File file : rootDirFile.listFiles()) {
                                files.add(file);
                            }

                            SecureRandom generator = SecureRandom.getInstance("SHA1PRNG");
                            while (files.size() > 0) {
                                // Get a random, positive integer
                                int fileToGet = Math.abs(generator.nextInt(files.size()));
                                File actual = files.remove(fileToGet);
                                // Don't confuse the expected results file as an actual results file
                                // if its in the same directory
                                if (!actual.isDirectory()
                                        && !expectedResultsFilename.equals(actual.getName())) {
                                    // process() populates tools with the supplied tool's results
                                    process(actual, expectedResults, tools, resultsFileCreator);
                                }
                            } // end while
                        } // end else
                    } // end if a directory
                } // end for loop through all files in the directory

                // process the results the normal way with a single results directory
            } else { // Not "mixed" - i.e., the 'Normal' way (being the same version of Benchmark
                // for all results)

                // Note that if there are two or more results files for the same version of the same
                // tool, each result file processed overwrites the previous results file for that
                // same tool, so you end up with only 1 scorecard for the last results file for that
                // tool that was processed.

                // Step 4b: Read the expected results so we know what each tool 'should do'
                File expected = new File(Configuration.expectedResultsFileName);
                TestSuiteResults expectedResults = readExpectedResults(expected);
                if (expectedResults == null) {
                    System.out.println("Couldn't read expected results file: " + expected);
                    System.exit(-1);
                } else {
                    System.out.println(
                            "Read expected results from file: " + expected.getAbsolutePath());
                    int totalResults = expectedResults.getTotalResults();
                    if (totalResults != 0) {
                        System.out.println(totalResults + " results found.");
                        TESTSUITEVERSION = expectedResults.getTestSuiteVersion();
                    } else {
                        System.out.println("Error! - zero expected results found in results file.");
                        System.exit(-1);
                    }
                }

                ResultsFileCreator resultsFileCreator =
                        new ResultsFileCreator(scoreCardDir, TESTSUITENAME);

                // Step 5b: Go through each result file and generate a scorecard for that tool.
                if (resultsFileOrDir.isDirectory()) {

                    if (!config.anonymousMode) {
                        boolean processedAtLeastOneResultsFile = false;
                        for (File actual : resultsFileOrDir.listFiles()) {
                            // Don't confuse the expected results file as an actual results file if
                            // its in the same directory
                            if (!actual.isDirectory()
                                    && !expected.getName().equals(actual.getName())) {
                                // process() populates tools with the supplied tool's results
                                process(actual, expectedResults, tools, resultsFileCreator);
                                processedAtLeastOneResultsFile = true;
                            }
                        }
                        if (!processedAtLeastOneResultsFile) {
                            System.out.println(
                                    "ERROR: No results files found in directory: "
                                            + resultsFileOrDir.getAbsolutePath());
                            System.exit(-1);
                        }
                    } else {
                        // To handle anonymous mode, we are going to randomly grab files out of this
                        // directory and process them. By doing it this way, multiple runs should
                        // randomly order the commercial tools each time.
                        List<File> files = new ArrayList<File>();
                        for (File file : resultsFileOrDir.listFiles()) {
                            files.add(file);
                        }

                        SecureRandom generator = SecureRandom.getInstance("SHA1PRNG");
                        while (files.size() > 0) {
                            int randomNum = generator.nextInt();
                            // FIXME: Get Absolute Value better
                            if (randomNum < 0) randomNum *= -1;
                            int fileToGet = randomNum % files.size();
                            File actual = files.remove(fileToGet);
                            // Don't confuse the expected results file as an actual results file if
                            // its in the same directory
                            if (!actual.isDirectory()
                                    && !expected.getName().equals(actual.getName())) {
                                // process() populates tools with the supplied tool's results
                                process(actual, expectedResults, tools, resultsFileCreator);
                            }
                        }
                    } // end else (!anonymousMode)

                } else {
                    // This will process a single results file, if that is what the 2nd parameter
                    // points to. This has never been used.
                    // process() populates tools with the supplied tool's results
                    process(resultsFileOrDir, expectedResults, tools, resultsFileCreator);
                } // end else ( f.isDirectory() )
            } // end else "Not mixed"

            System.out.println("Tool scorecards computed.");

            // catch try for Steps 4 & 5
        } catch (Exception e) {
            System.err.println("Error during processing: " + e.getMessage());
            e.printStackTrace();
        }

        // Step 6: Generate scorecards for each vulnerability type across all the tools now that
        // the results for all the individual tools have been calculated.

        // First, we have to figure out all the vulnerability types that were scored
        // A set is used here to eliminate duplicate vuln types across all the results
        Set<String> vulnSet = new TreeSet<String>();
        for (Tool tool : tools) {
            vulnSet.addAll(tool.getOverallMetrics().getCategories());
        }

        // Then we generate a scorecard for each vuln type
        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(TESTSUITENAME, TESTSUITEVERSION);
        BenchmarkScore.generateVulnerabilityScorecards(
                tools, vulnSet, scoreCardDir, commercialAveragesTable, false);
        System.out.println("Vulnerability scorecards computed.");

        // Step 7: Generate the tool scorecards now that the overall Vulnerability scorecards and
        // stats have been calculated
        ToolScorecard toolScorecard =
                new ToolScorecard(
                        BenchmarkScore.overallAveToolMetrics, scoreCardDir, config, TESTSUITENAME);

        for (Tool tool : tools) {
            toolScorecard.generate(tool, tool.getOverallMetrics().getCategoryMetrics());
        }

        // Optional Step 8: If CategoryGroups are enabled do steps 8a & 8b
        // Step 8a: generate scorecards for each CategoryGroup across all the tools

        Set<String> catGroupsSet = new TreeSet<String>();
        if (CategoryGroups.isCategoryGroupsEnabled()) {
            try {
                // Figure out the set of CategoryGroups that were scored
                // A set is used here to eliminate duplicate category groups across all the results
                for (Tool tool : tools) {
                    catGroupsSet.addAll(tool.getCategoryGroups());
                }

                // Then we generate a scorecard for each category group
                CommercialAveragesTable commercialCategoryGroupAveragesTable =
                        new CommercialAveragesTable(TESTSUITENAME, TESTSUITEVERSION, true);
                BenchmarkScore.generateVulnerabilityScorecards(
                        tools,
                        catGroupsSet,
                        scoreCardDir,
                        commercialCategoryGroupAveragesTable,
                        true);
                System.out.println("Category Group scorecards computed.");

                // Step 8b: Generate the tool scorecards now that the overall Vulnerability
                // scorecards and stats have been calculated for CategoryGroups
                ToolScorecard toolScorecardCatGroups =
                        new ToolScorecard(
                                BenchmarkScore.overallAveToolMetrics,
                                scoreCardDir,
                                config,
                                TESTSUITENAME);

                for (Tool tool : tools) {
                    toolScorecardCatGroups.generate(tool, tool.getCategoryGroupMetrics(), true);
                }

            } catch (Exception e) {
                System.out.println(
                        "Error invoking BenchmarkScore.generateVulnerabilityScorecards() w/CategoryGroups enabled.");
                e.printStackTrace();
                System.exit(-1);
            }
        }

        // Step 9: Update all the menus for all the generated pages to reflect the tools and
        // vulnerability categories
        new MenuUpdater(
                        config,
                        TESTSUITENAME,
                        TESTSUITEVERSION,
                        commercialAveragesTable,
                        tools,
                        vulnSet,
                        catGroupsSet,
                        scoreCardDir,
                        toolScorecard)
                .updateMenus();

        // Step 10: Generate the overall comparison chart for all the tools in this test
        ScatterHome.generateComparisonChart(tools, config.focus, scoreCardDir);

        // Step 11: Generate the results table across all the tools in this test
        try {
            OverallStatsTable overallStatsTable = new OverallStatsTable(config, TESTSUITENAME);

            String html =
                    new String(Files.readAllBytes(homeFilePath))
                            .replace("${projectlink}", config.report.html.projectLinkEntry)
                            .replace("${table}", overallStatsTable.generateFor(tools))
                            .replace("${tprlabel}", config.tprLabel)
                            .replace(
                                    "${precisionkey}",
                                    config.report.html.precisionKeyEntry
                                            + config.report.html.fsCoreEntry);

            Files.write(homeFilePath, html.getBytes());
        } catch (IOException e) {
            System.err.println("Error updating results table in: " + homeFilePath.getFileName());
            e.printStackTrace();
        }

        // Step 12: Create Interpretation Guide image with name of this particular test suite
        ScatterInterpretation scatter = new ScatterInterpretation(800);
        try {
            scatter.writeChartToFile(new File(scoreCardDir, "content/testsuite_guide.png"), 800);
        } catch (IOException e) {
            System.err.println(
                    "ERROR: Couldn't create content/testsuite_guide.png file for some reason.");
            e.printStackTrace();
        }

        System.out.println(BenchmarkScore.TESTSUITENAME.simpleName() + " scorecards complete.");

        System.exit(0);
    }

    /**
     * The method takes in a tool scan results file and determines how well that tool did against
     * the test suite. And then it generates the HTML scorecard for that tool as writes it to disk.
     *
     * @param rawToolResultsFile - The raw results file to process. This is the native results file
     *     from the tool.
     * @param expectedResults - This is the expected results csv file for this version of the test
     *     suite.
     * @param tools - The current set of tools. This contains information about the results for each
     *     tool. It is updated in this method so that the menus across all the scorecards can be
     *     generated later and a summary scorecard can be computed. A new Tool is added each time
     *     this method is called which adds the name of the tool, the filename of the scorecard, and
     *     the report that was created for that tool.
     * @param resultsFileCreator - Creates results file for given tools
     */
    private static void process(
            File rawToolResultsFile,
            TestSuiteResults expectedResults,
            Set<Tool> tools,
            ResultsFileCreator resultsFileCreator) {

        try {
            String resultsFileName = rawToolResultsFile.getName();
            // If the filename starts with a . ignore it
            if (resultsFileName.startsWith(".")) return;

            // Figure out the actual results for this tool from the raw results file for this tool
            System.out.println("\nAnalyzing results from " + resultsFileName);
            TestSuiteResults rawToolResults = readActualResults(rawToolResultsFile);

            if (expectedResults != null && rawToolResults != null) {

                // Combining results from multiple results files if the 'combine' results flag is
                // enabled.
                if (config.combineResultsMode) {

                    // Get the toolname and version so you can look to find a match
                    String toBeProcessedToolnameAndVersion = rawToolResults.getToolNameAndVersion();

                    Iterator<Tool> toolsIterator = tools.iterator();
                    while (toolsIterator.hasNext()) {
                        Tool tool = toolsIterator.next();
                        if (tool.getToolNameAndVersion().equals(toBeProcessedToolnameAndVersion)) {
                            Tool sameToolAndVersion = tool;
                            System.out.println(
                                    "Combining results for matching tool and version: "
                                            + toBeProcessedToolnameAndVersion);

                            // Merge the results together so we can calculate combined results.
                            TestSuiteResults prevToolResults = tool.getActualResults();
                            rawToolResults.combineResults(prevToolResults);

                            // Now that we've combined the previous results into a single results
                            // set,
                            // remove the existing Tool results so we can calculated combined
                            // results below, and add a new result to the set of tool results.
                            tools.remove(sameToolAndVersion);
                            break;
                        }
                    } // end while. If we don't find a match, we simply drop through as this is a
                    // new tool
                }

                // note: side effect is that "pass/fail" value is set for each expected result so it
                // can be used to produce scorecard for this tool. CweMatch details are set too.
                TestSuiteResults actualResults = analyze(expectedResults, rawToolResults);

                // Produce a .csv results file of the actual results, except if its a commercial
                // tool, and we are in showAveOnly mode.
                String actualResultsFileName = "notProduced";
                if (!(config.showAveOnlyMode && rawToolResults.isCommercial)) {
                    actualResultsFileName = resultsFileCreator.createFor(actualResults);
                }

                Map<String, TP_FN_TN_FP_Counts> scores = calculateScores(actualResults);

                ToolMetrics metrics = calculateMetrics(scores);
                metrics.setScanTime(rawToolResults.getTime());

                Tool tool =
                        new Tool(
                                // TODO FIXME: When sending in the 'actual' results, this causes ALL
                                // the TPs and FPs to be reported for each tool, so leaving as
                                // rawToolResults for now.
                                rawToolResults,
                                scores,
                                metrics,
                                actualResultsFileName,
                                rawToolResults.isCommercial());

                // Add this tool to the set of tools processed so far
                tools.add(tool);

                // This is for debugging purposes. It indicates how may extra results were found in
                // the actual results vice the expected results.
                // printExtraCWE( expectedResults, actualResults );
            } else {
                if (expectedResults == null) {
                    System.err.println("Error!!: expected results were null.");
                } else
                    System.err.println(
                            "Error!!: actual results were null for file: " + rawToolResultsFile);
            }
        } catch (Exception e) {
            System.err.println("Error processing " + rawToolResultsFile + ". Continuing.");
            e.printStackTrace();
        }
    }

    // Don't delete - for debug purposes
    @SuppressWarnings("unused")
    private static void printExtraCWE(
            TestSuiteResults expectedResults, TestSuiteResults actualResults) {
        Set<Integer> expectedCWE = new HashSet<Integer>();
        for (String testcase : expectedResults.keySet()) {
            List<TestCaseResult> list = expectedResults.getTestCaseResults(testcase);
            for (TestCaseResult t : list) {
                expectedCWE.add(t.getCWE());
            }
        }

        Set<Integer> actualCWE = new HashSet<Integer>();
        for (String testcase : actualResults.keySet()) {
            List<TestCaseResult> list = actualResults.getTestCaseResults(testcase);
            if (list != null) {
                for (TestCaseResult t : list) {
                    actualCWE.add(t.getCWE());
                }
            }
        }

        Set<Integer> extras = difference(actualCWE, expectedCWE);
        for (int cwe : extras) {
            System.out.println("Extra: " + cwe);
        }
    }

    public static <T> Set<T> difference(Set<T> setA, Set<T> setB) {
        Set<T> tmp = new HashSet<T>(setA);
        tmp.removeAll(setB);
        return tmp;
    }

    private static ToolMetrics calculateMetrics(
            Map<String, TP_FN_TN_FP_Counts> allCategoryResults) {

        ToolMetrics metrics = new ToolMetrics();
        double totalFPRate = 0;
        double totalTPRate = 0;
        int total = 0;
        int totalTP = 0;
        int totalFP = 0;
        int totalFN = 0;
        int totalTN = 0;
        for (String category : allCategoryResults.keySet()) {
            // Calculate the metrics for this category
            TP_FN_TN_FP_Counts c = allCategoryResults.get(category);
            int rowTotal = c.tp + c.fn + c.tn + c.fp;
            double precision = (double) c.tp / (double) (c.tp + c.fp);
            // c.tp & c.fp can both be zero, creating a precision of NaN. So set to 0.0.
            if (Double.isNaN(precision)) precision = 0.0;
            double tpr = (double) c.tp / (double) (c.tp + c.fn);
            // c.tp & c.fn can both be zero, creating an tpr of NaN. So set to 0.0.
            if (Double.isNaN(tpr)) tpr = 0.0;
            double fpr = (double) c.fp / (double) (c.fp + c.tn);
            // c.fp & c.tn can both be zero, creating an fpr of NaN. So set to 0.0.
            if (Double.isNaN(fpr)) fpr = 0.0;

            // Add the metrics for this particular category. This add() doesn't automatically
            // update the tool's overall metrics, so those are calculated after this loop completes.
            metrics.addCategoryMetrics(category, precision, tpr, fpr, rowTotal);

            // Update the tool wide totals
            totalFPRate += fpr;
            totalTPRate += tpr;
            total += rowTotal;
            totalTP += c.tp;
            totalFP += c.fp;
            totalFN += c.fn;
            totalTN += c.tn;
        } // end for

        // Calculate and set metrics across all categories
        int numCategories = allCategoryResults.size();
        double totalPrecision = (double) totalTP / (double) (totalTP + totalFP);
        // tp & fp can both be zero, creating a precision of NaN. If so, set to 0.0.
        if (Double.isNaN(totalPrecision)) totalPrecision = 0.0;
        metrics.setPrecision(totalPrecision);
        metrics.setFalsePositiveRate(totalFPRate / numCategories);
        metrics.setTruePositiveRate(totalTPRate / numCategories);
        metrics.setTotalTestCases(total);
        metrics.setOverallFindingCounts(totalTP, totalFP, totalFN, totalTN);

        return metrics;
    }

    /**
     * This method translates vulnerability names, e.g., Cross-Site Scripting, to their CWE number.
     *
     * @param categoryName - The category to translate.
     * @return The CWE # of that category.
     */
    public static int translateNameToCWE(String categoryName) {
        int cwe;

        Category category = Categories.getCategoryByLongName(categoryName);
        if (category == null) {
            System.err.println("ERROR: Category: " + categoryName + " not supported.");
            cwe = -1;
        } else {
            cwe = category.getCWE();
        }

        return cwe;
    }

    /**
     * Return map of each vuln category to the actual result counts for that category in the
     * supplied TestSuiteResults.
     *
     * @param actualResults - Results to calculate scores from.
     * @return A Map<String, TP_FN_TN_FP_Counts> of the vuln categories by name, to the scores for
     *     this tool.
     */
    private static Map<String, TP_FN_TN_FP_Counts> calculateScores(TestSuiteResults actualResults) {
        Map<String, TP_FN_TN_FP_Counts> map = new TreeMap<String, TP_FN_TN_FP_Counts>();

        for (String testcase : actualResults.keySet()) {
            TestCaseResult tcr = actualResults.getTestCaseResults(testcase).get(0); // only one
            String cat = Categories.getCategoryById(tcr.getCategory()).getName();

            TP_FN_TN_FP_Counts c = map.get(cat);
            if (c == null) {
                c = new TP_FN_TN_FP_Counts();
                map.put(cat, c);
            }
            // real vulnerabilities
            if (tcr.isTruePositive() && tcr.isPassed()) c.tp++; // tp
            else if (tcr.isTruePositive() && !tcr.isPassed()) c.fn++; // fn

            // fake vulnerabilities
            else if (!tcr.isTruePositive() && tcr.isPassed()) c.tn++; // tn
            else if (!tcr.isTruePositive() && !tcr.isPassed()) c.fp++; // fp
        }
        return map;
    }

    private static TestSuiteResults readActualResults(File fileToParse) throws Exception {
        ResultFile resultFile = new ResultFile(fileToParse);
        TestSuiteResults tr = null;

        Optional<Reader> reader =
                Reader.allReaders().stream().filter(r -> r.canRead(resultFile)).findAny();

        if (reader.isPresent()) {
            tr = reader.get().parse(resultFile);
        }

        // If we have results, see if the version # is in the results file name.
        if (tr != null) {
            // If version # specified in the results file name, extract it, and set it.
            // For example: Benchmark-1.1-Coverity-results-v1.3.2661-6720.json  (the version # is
            // 1.3.2661 in this example).
            // This code should also handle: Benchmark-1.1-Coverity-results-v1.3.2661.xml (where the
            // compute time '-6720' isn't specified)
            int indexOfVersionMarker = resultFile.filename().lastIndexOf("-v");
            if (indexOfVersionMarker != -1) {
                String restOfFileName = resultFile.filename().substring(indexOfVersionMarker + 2);
                int endIndex = restOfFileName.lastIndexOf('-');
                if (endIndex == -1) endIndex = restOfFileName.lastIndexOf('.');
                String version = restOfFileName.substring(0, endIndex);
                tr.setToolVersion(version);
            }
        }

        return tr;
    }

    /**
     * Go through each expected result, and figure out if this tool actually passed or not. This
     * updates the expected results to reflect what passed/failed and also add CweMatch details to
     * each TestCaseResult so we know the details of exactly how a True Positive passed, or a False
     * Positive failed.
     *
     * <p>The vendor-specific category in the actual TestSuiteResults is matched to the
     * corresponding expected tests by CWE number in the expected TestResults, looking for either an
     * exact CWE match or a ParentOf/ChildOf CWE match.
     *
     * @param expected - The expected results for this test suite.
     * @param rawToolResults - The actual results for this tool
     * @return The scored results for this tool, which is the expected results modified with the how
     *     the tool did compared to the expected results.
     */
    private static TestSuiteResults analyze(
            TestSuiteResults expected, TestSuiteResults rawToolResults) {

        // Set the version of the test suite these actual results are being compared against
        rawToolResults.setTestSuiteVersion(expected.getTestSuiteVersion());

        // If in anonymous mode, anonymize the tool name if its a commercial tool before its used to
        // compute anything, unless its the tool of 'focus'.
        if (config.anonymousMode
                && rawToolResults.isCommercial
                && !rawToolResults.getToolName().replace(' ', '_').equalsIgnoreCase(config.focus)) {
            rawToolResults.setAnonymous();
        }

        for (String testcase : expected.keySet()) {
            TestCaseResult exp = expected.getTestCaseResults(testcase).get(0); // always only one!
            List<TestCaseResult> act =
                    rawToolResults.getTestCaseResults(
                            testcase); // could be lots of results for this test

            CweMatchDetails cweMatch = compare(exp, act, rawToolResults.getToolName());

            // helpful in debugging
            // System.out.println( testcase + ", " + exp.getCategory() + ", " + exp.isTruePositive()
            // + "," + exp.getCWE() + ", " + pass + "\n");

            // Add the actual results to the "expected" results so we can score the tool
            exp.setPassed(cweMatch.pass);
            exp.addMatchDetails(cweMatch);
        }

        // Record the name, version, and type of the tool whose pass/fail values were recorded in
        // 'expected' results
        expected.setTool(rawToolResults.getToolName());
        expected.setToolVersion(rawToolResults.getToolVersion());
        expected.setToolType(rawToolResults.getToolType());

        // Return the modified expected as the actual.  Beware of the side effect!
        return expected;
    }

    /**
     * Check all actual results. If a reported vulnerability matches, then exit. Otherwise keep
     * going.
     *
     * @param exp The expected results
     * @param actList The list of actual results for this test case.
     * @return true if the expected result matches the actual result (i.e., If True Positive, that
     *     results was found, If False Positive, that result was not found.)
     */
    private static CweMatchDetails compare(
            TestCaseResult exp, List<TestCaseResult> actList, String tool) {

        int expectedCWE = exp.getCWE();

        // return true if there are no actual results and this was a false positive test
        if (actList == null || actList.isEmpty()) {
            return new CweMatchDetails(
                    expectedCWE, exp.isTruePositive(), !exp.isTruePositive(), -1, "", actList);
        }

        // Check actual results for an exact CWE match.
        for (TestCaseResult act : actList) {
            // Helpful in debugging
            // System.out.println( "  Evidence: " + act.getCWE() + " " + act.getEvidence() + "[" +
            // act.getConfidence() + "]");

            int actualCWE = act.getCWE();

            // immediately return a value if we find an exact match
            if (actualCWE == expectedCWE) {
                return new CweMatchDetails(
                        expectedCWE,
                        exp.isTruePositive(),
                        exp.isTruePositive(),
                        actualCWE,
                        "",
                        actList);
            }
        }

        // If no exact match, we look through results again looking for a ChildOf or ParentOf match
        for (TestCaseResult act : actList) {
            int actualCWE = act.getCWE();
            Category expectedCWECategory = Categories.getCategoryByCWE(expectedCWE);

            if (expectedCWECategory.isChildOf(actualCWE)) {
                return new CweMatchDetails(
                        expectedCWE,
                        exp.isTruePositive(),
                        exp.isTruePositive(),
                        actualCWE,
                        "ChildOf",
                        actList);
            }
            if (expectedCWECategory.isParentOf(actualCWE)) {
                return new CweMatchDetails(
                        expectedCWE,
                        exp.isTruePositive(),
                        exp.isTruePositive(),
                        actualCWE,
                        "ParentOf",
                        actList);
            }
        }
        // if we couldn't find a match, then return true if it's a False Positive test
        return new CweMatchDetails(
                expectedCWE, exp.isTruePositive(), !exp.isTruePositive(), -1, "", actList);
    }

    // Create a TestResults object that contains the expected results for this version
    // of the test suite.
    private static TestSuiteResults readExpectedResults(File file) {
        try {
            TestSuiteResults tr = ExpectedResultsProvider.parse(new ResultFile(file));

            BenchmarkScore.TESTSUITENAME = new TestSuiteName(tr.getTestSuiteName());
            BenchmarkScore.TESTCASENAME = tr.getTestSuiteName() + BenchmarkScore.TEST;

            return tr;
        } catch (FileNotFoundException e) {
            System.err.println("ERROR: Can't find expected results file: " + file);
            System.exit(-1);
        } catch (IOException e) {
            System.err.println("ERROR: Reading contents of expected results file: " + file);
            e.printStackTrace();
            System.exit(-1);
        }

        return null;
    }

    /**
     * Generate all the vulnerability scorecards and 1 commercial tool average scorecard if there
     * are commercial tool results for at least 2 commercial tools, and write them to disk. Also
     * calculate the Tool metrics for: averageCommercialToolMetrics,
     * averageNonCommercialToolMetrics, overallAveToolMetrics.
     *
     * @param tools The set of tool results for the tools to chart
     * @param catSet The vuln categories or categoryGroups to generate this for
     * @param scoreCardDir The directory to write the generated chart to
     * @param commercialAveragesTable The average results of the commercial tools to compare each
     *     commercial tool to
     * @param useCategoryGroups If true, the specified category refers to a CategoryGroup not a vuln
     *     Category
     */
    private static void generateVulnerabilityScorecards(
            Set<Tool> tools,
            Set<String> catSet,
            File scoreCardDir,
            CommercialAveragesTable commercialAveragesTable,
            boolean useCategoryGroups) {

        // A side effect of this method is to calculate these averages
        BenchmarkScore.averageCommercialToolMetrics = new HashMap<String, CategoryMetrics>();
        BenchmarkScore.averageNonCommerciaToolMetrics = new HashMap<String, CategoryMetrics>();
        BenchmarkScore.overallAveToolMetrics = new HashMap<String, CategoryMetrics>();

        final ClassLoader CL = BenchmarkScore.class.getClassLoader();

        VulnerabilityStatsTable vulnerabilityStatsTable =
                new VulnerabilityStatsTable(config, TESTSUITENAME, tools);

        for (String cat : catSet) {
            try {
                // Generate a comparison chart for all tools for this vuln category or
                // CategoryGroup. When constructed, scatter contains the Overall, Non-commercial,
                // and Commercial stats for this category across all tools.
                ScatterVulns scatter =
                        ScatterVulns.generateComparisonChart(
                                cat, tools, config.focus, scoreCardDir, useCategoryGroups);

                // Before creating HTML for this vuln category or category group, save the category
                // level results into averageCommercialToolResults, averageNonCommerciaToolResults,
                // overallAveToolResults
                BenchmarkScore.averageCommercialToolMetrics.put(
                        cat, scatter.getCommercialCategoryMetrics());
                BenchmarkScore.averageNonCommerciaToolMetrics.put(
                        cat, scatter.getNonCommercialCategoryMetrics());
                BenchmarkScore.overallAveToolMetrics.put(cat, scatter.getOverallCategoryMetrics());

                String filename =
                        TESTSUITENAME.simpleName()
                                + "_v"
                                + TESTSUITEVERSION
                                + "_Scorecard_for_"
                                + cat.replace(' ', '_');
                File htmlFile = new File(scoreCardDir, filename + ".html");

                // Resources in a jar file have to be loaded as streams, not directly as Files.
                final String VULNTEMPLATERESOURCE = "scorecard/vulntemplate.html";
                InputStream vulnTemplateStream = CL.getResourceAsStream(VULNTEMPLATERESOURCE);
                if (vulnTemplateStream == null) {
                    System.out.println(
                            "ERROR - vulnTemplate stream is null for resource: "
                                    + VULNTEMPLATERESOURCE);
                }

                String html = IOUtils.toString(vulnTemplateStream, StandardCharsets.UTF_8);
                html = html.replace("${testsuite}", BenchmarkScore.TESTSUITENAME.fullName());
                String addCatalogGroupDetails = "";
                if (CategoryGroups.isCategoryGroupsEnabled()) {
                    addCatalogGroupDetails +=
                            (useCategoryGroups
                                    ? "CWE Group: "
                                    : "CWE-" + BenchmarkScore.translateNameToCWE(cat) + ": ");
                }
                String fullTitle =
                        BenchmarkScore.TESTSUITENAME.fullName()
                                + " Scorecard for "
                                + addCatalogGroupDetails
                                + cat;

                html = html.replace("${image}", filename + ".png");
                html = html.replace("${title}", fullTitle);
                html =
                        html.replace(
                                "${vulnerability}",
                                (useCategoryGroups
                                                ? ""
                                                : "CWE-"
                                                        + BenchmarkScore.translateNameToCWE(cat)
                                                        + ": ")
                                        + cat);
                html = html.replace("${version}", TESTSUITEVERSION);
                html = html.replace("${projectlink}", config.report.html.projectLinkEntry);

                html =
                        html.replace(
                                "${table}",
                                vulnerabilityStatsTable.generateFor(cat, useCategoryGroups));
                html = html.replace("${tprlabel}", config.tprLabel);
                html =
                        html.replace(
                                "${precisionkey}",
                                config.report.html.precisionKeyEntry
                                        + config.report.html.fsCoreEntry);

                // Add optional details of test cases per CWE included in a Category Group
                html =
                        html.replace(
                                "${CategoryGroupDetailsTitle}",
                                (useCategoryGroups
                                        ? "<h2>Test Case Counts for CWEs Included in this Group</h2>"
                                        : ""));
                html =
                        html.replace(
                                "${CategoryGroupDetailsTable}",
                                generateCategoryGroupDetailsTable(cat, useCategoryGroups));

                Files.write(htmlFile.toPath(), html.getBytes());

                // Only build commercial stats scorecard if there are 2+ commercial tools
                if (scatter.getCommercialToolCount() > 1) {
                    commercialAveragesTable.add(scatter);
                }

            } catch (IOException e) {
                System.out.println("Error generating vulnerability summaries: " + e.getMessage());
                e.printStackTrace();
            }
        } // end for loop

        if (commercialAveragesTable.hasEntries()) {
            try {
                Path htmlfile =
                        Paths.get(
                                scoreCardDir.getAbsolutePath()
                                        + File.separator
                                        + commercialAveragesTable.filename(useCategoryGroups));
                // Resources in a jar file have to be loaded as streams, not directly as Files.
                InputStream vulnTemplateStream =
                        CL.getResourceAsStream(scoreCardDir + "/commercialAveTemplate.html");
                String html = IOUtils.toString(vulnTemplateStream, StandardCharsets.UTF_8);
                html = html.replace("${testsuite}", BenchmarkScore.TESTSUITENAME.fullName());
                html = html.replace("${version}", TESTSUITEVERSION);
                html = html.replace("${projectlink}", config.report.html.projectLinkEntry);

                html = html.replace("${table}", commercialAveragesTable.render());
                html = html.replace("${tprlabel}", config.tprLabel);
                html =
                        html.replace(
                                "${precisionkey}",
                                config.report.html.precisionKeyEntry
                                        + config.report.html.fsCoreEntry);

                Files.write(htmlfile, html.getBytes());
                System.out.println("Commercial average scorecard computed.");
            } catch (IOException e) {
                System.out.println("Error generating commercial scorecard: " + e.getMessage());
                e.printStackTrace();
            }
        } // end if commercialAveragesTable.hasEntries()
    }

    private static String generateCategoryGroupDetailsTable(
            String categoryGroup, boolean useCategoryGroups) {
        if (!useCategoryGroups) return "";
        HtmlStringBuilder htmlBuilder = new HtmlStringBuilder();

        htmlBuilder.beginTable("table");

        htmlBuilder.beginTr();
        htmlBuilder.th("CWE");
        htmlBuilder.th("Vulnerability Category");
        htmlBuilder.th("TPs");
        htmlBuilder.th("FPs");
        htmlBuilder.th("Total");
        htmlBuilder.endTr();

        CategoryGroup currentGroup = CategoryGroups.getCategoryGroupByName(categoryGroup);
        Set<Integer> cweList = currentGroup.getCWEs();

        // Create a sorted list by Vuln Category name (e.g., Hard-coded Password) where there are
        // testcases in a CWE in this CategoryGroup
        SortedMap<String, Integer> sortedCWEList = new TreeMap<>();
        for (int cwe : cweList) {
            CountsPerCWE cweCounts = ExpectedResultsProvider.getTestcaseCountsForCWE(cwe);
            if (cweCounts != null) {
                Category cat = Categories.getCategoryByCWE(cwe);
                sortedCWEList.put(cat.getName(), Integer.valueOf(cwe));
            }
        }

        // Loop through sortedCWEList and add a row for each CWE with these details to the table
        int totalTpCount = 0, totalFpCount = 0, totalCount = 0;
        for (String vulnType : sortedCWEList.keySet()) {
            Integer CWE = sortedCWEList.get(vulnType);
            CountsPerCWE cweCounts = ExpectedResultsProvider.getTestcaseCountsForCWE(CWE);
            htmlBuilder.beginTr();
            htmlBuilder.td(CWE);
            htmlBuilder.td(vulnType);
            int tpCountForCWE = cweCounts.getTPCount();
            totalTpCount += tpCountForCWE;
            htmlBuilder.td(tpCountForCWE);
            int fpCountForCWE = cweCounts.getFPCount();
            totalFpCount += fpCountForCWE;
            htmlBuilder.td(fpCountForCWE);
            int countTotalForCWE = tpCountForCWE + fpCountForCWE;
            totalCount += countTotalForCWE;
            htmlBuilder.td(countTotalForCWE);
            htmlBuilder.endTr();
        }

        // And final total row
        htmlBuilder.beginTr();
        htmlBuilder.td("<b>Grand Total</b>");
        htmlBuilder.td("");
        htmlBuilder.td("<b>" + totalTpCount + "</b>");
        htmlBuilder.td("<b>" + totalFpCount + "</b>");
        htmlBuilder.td("<b>" + totalCount + "</b>");
        htmlBuilder.endTr();

        htmlBuilder.endTable();

        return htmlBuilder.toString();
    }
}
