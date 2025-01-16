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
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
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
import org.owasp.benchmarkutils.helpers.Utils;
import org.owasp.benchmarkutils.score.domain.TestSuiteName;
import org.owasp.benchmarkutils.score.parsers.Reader;
import org.owasp.benchmarkutils.score.report.ScatterHome;
import org.owasp.benchmarkutils.score.report.ScatterInterpretation;
import org.owasp.benchmarkutils.score.report.ScatterVulns;
import org.owasp.benchmarkutils.score.report.html.CommercialAveragesTable;
import org.owasp.benchmarkutils.score.report.html.MenuUpdater;
import org.owasp.benchmarkutils.score.report.html.OverallStatsTable;
import org.owasp.benchmarkutils.score.report.html.ToolScorecard;
import org.owasp.benchmarkutils.score.report.html.VulnerabilityStatsTable;
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

    // The values stored in this is pulled from the categories.xml config file
    //    public static Categories CATEGORIES;

    /*
     * The set of all the Tools. Each Tool includes the results for that tool.
     */
    private static Set<Tool> tools = new TreeSet<Tool>();

    // These Average Category values are computed as a side effect of running
    // generateVulnerabilityScorecards().
    private static Map<String, CategoryResults> averageCommercialToolResults = null;
    private static Map<String, CategoryResults> averageNonCommerciaToolResults = null;
    private static Map<String, CategoryResults> overallAveToolResults = null;

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
     * -Pscorecard -Dexec.args="-cf ../julietjs/config/julietscoringconfig.yaml"
     *
     * @param args - The command line arguments.
     */
    public static void main(String[] args) {
        try {
            loadConfigFromCommandLineArguments(args);
        } catch (RuntimeException e) {
            System.out.println("Error processing configuration for Scoring. Aborting.");
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
            } else { // Not "mixed" - i.e., the 'Normal' way

                // Step 4b: Read the expected results so we know what each tool 'should do'
                File expected = new File(config.expectedResultsFileName);
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
            System.out.println("Error during processing: " + e.getMessage());
            e.printStackTrace();
        }

        // Step 6: Generate scorecards for each type of vulnerability across all the tools now that
        // the results for all the individual tools have been calculated.

        // First, we have to figure out the set of vulnerability types that were scored
        // A set is used here to eliminate duplicate categories across all the results
        Set<String> catSet = new TreeSet<String>();
        for (Tool tool : tools) {
            catSet.addAll(tool.getOverallResults().getCategories());
        }

        // Then we generate each vulnerability scorecard
        CommercialAveragesTable commercialAveragesTable =
                new CommercialAveragesTable(TESTSUITENAME, TESTSUITEVERSION);
        BenchmarkScore.generateVulnerabilityScorecards(
                tools, catSet, scoreCardDir, commercialAveragesTable);
        System.out.println("Vulnerability scorecards computed.");

        // Step 7: Generate the tool scorecards now that the overall Vulnerability scorecards and
        // stats have been calculated
        ToolScorecard toolScorecard =
                new ToolScorecard(overallAveToolResults, scoreCardDir, config, TESTSUITENAME);

        tools.forEach(toolScorecard::generate);

        // Step 8: Update all the menus for all the generated pages to reflect the tools and
        // vulnerability categories
        new MenuUpdater(
                        config,
                        TESTSUITENAME,
                        TESTSUITEVERSION,
                        commercialAveragesTable,
                        tools,
                        catSet,
                        scoreCardDir,
                        toolScorecard)
                .updateMenus();

        // Step 9: Generate the overall comparison chart for all the tools in this test
        ScatterHome.generateComparisonChart(tools, config.focus, scoreCardDir);

        // Step 10: Generate the results table across all the tools in this test
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
            System.out.println("Error updating results table in: " + homeFilePath.getFileName());
            e.printStackTrace();
        }

        // Step 11: Create the Interpretation Guide image with the name of this particular test
        // suite
        ScatterInterpretation scatter = new ScatterInterpretation(800);
        try {
            scatter.writeChartToFile(new File(scoreCardDir, "content/testsuite_guide.png"), 800);
        } catch (IOException e) {
            System.out.println(
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
            // System.out.println("Computed actual results for tool: " + actualResults.getTool());

            if (expectedResults != null && rawToolResults != null) {
                // note: side effect is that "pass/fail" value is set for each expected result so it
                // can be used to produce scorecard for this tool
                TestSuiteResults actualResults = analyze(expectedResults, rawToolResults);

                // Produce a .csv results file of the actual results, except if its a commercial
                // tool, and we are in showAveOnly mode.
                String actualResultsFileName = "notProduced";
                if (!(config.showAveOnlyMode && rawToolResults.isCommercial)) {
                    actualResultsFileName = resultsFileCreator.createFor(actualResults);
                }

                Map<String, TP_FN_TN_FP_Counts> scores = calculateScores(actualResults);

                ToolResults metrics = calculateMetrics(scores);
                metrics.setScanTime(rawToolResults.getTime());

                Tool tool =
                        new Tool(
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
                    System.out.println("Error!!: expected results were null.");
                } else
                    System.out.println(
                            "Error!!: actual results were null for file: " + rawToolResultsFile);
            }
        } catch (Exception e) {
            System.out.println("Error processing " + rawToolResultsFile + ". Continuing.");
            e.printStackTrace();
        }
    }

    // Don't delete - for debug purposes
    @SuppressWarnings("unused")
    private static void printExtraCWE(
            TestSuiteResults expectedResults, TestSuiteResults actualResults) {
        Set<Integer> expectedCWE = new HashSet<Integer>();
        for (int i : expectedResults.keySet()) {
            List<TestCaseResult> list = expectedResults.get(i);
            for (TestCaseResult t : list) {
                expectedCWE.add(t.getCWE());
            }
        }

        Set<Integer> actualCWE = new HashSet<Integer>();
        for (int i : actualResults.keySet()) {
            List<TestCaseResult> list = actualResults.get(i);
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

    private static ToolResults calculateMetrics(Map<String, TP_FN_TN_FP_Counts> results) {

        ToolResults metrics = new ToolResults();
        double totalFPRate = 0;
        double totalTPRate = 0;
        int total = 0;
        int totalTP = 0;
        int totalFP = 0;
        int totalFN = 0;
        int totalTN = 0;
        for (String category : results.keySet()) {
            TP_FN_TN_FP_Counts c = results.get(category);
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

            totalFPRate += fpr;
            totalTPRate += tpr;
            total += rowTotal;
            totalTP += c.tp;
            totalFP += c.fp;
            totalFN += c.fn;
            totalTN += c.tn;

            // Add the metrics for this particular category. But this add() doesn't automatically
            // update the overall metrics, so those are set after this for loop completes.
            metrics.add(category, precision, tpr, fpr, rowTotal);
        } // end for

        int resultsSize = results.size();
        double totalPrecision = (double) totalTP / (double) (totalTP + totalFP);
        // tp & fp can both be zero, creating a precision of NaN. If so, set to 0.0.
        if (Double.isNaN(totalPrecision)) totalPrecision = 0.0;
        metrics.setPrecision(totalPrecision);
        metrics.setFalsePositiveRate(totalFPRate / resultsSize);
        metrics.setTruePositiveRate(totalTPRate / resultsSize);
        metrics.setTotalTestCases(total);
        metrics.setFindingCounts(totalTP, totalFP, totalFN, totalTN);

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

        Category category = Categories.getByName(categoryName);
        if (category == null) {
            System.out.println("Error: Category: " + categoryName + " not supported.");
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

        for (Integer tn : actualResults.keySet()) {
            TestCaseResult tcr = actualResults.get(tn).get(0); // only one
            String cat = Categories.getById(tcr.getCategory()).getName();

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
     * updates the expected results to reflect what passed/failed.
     *
     * <p>The vendor-specific category in TestSuiteResults actual is not used. The actual tests are
     * matched to the corresponding expected tests by CWE numberBenchmark-specific category in
     * TestResults expected, and the Benchmark-specific category in TestResults expected is used
     * instead.
     *
     * <p>TODO: Do not cause the side effect by modifying expected.
     *
     * @param expected - The expected results for this test suite.
     * @param rawToolResults - The actual results for this tool
     * @return The scored results for this tool.
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

        boolean pass = false;
        for (int tc : expected.keySet()) {
            TestCaseResult exp = expected.get(tc).get(0); // always only one!
            List<TestCaseResult> act =
                    rawToolResults.get(tc); // could be lots of results for this test

            pass = compare(exp, act, rawToolResults.getToolName());

            // helpful in debugging
            // System.out.println( tc + ", " + exp.getCategory() + ", " + exp.isTruePositive() + ",
            // " +
            // exp.getCWE() + ", " + pass + "\n");

            // fill the result into the "expected" results in case we need it later
            exp.setPassed(pass);
        }

        // Record the name and version of the tool whose pass/fail values were recorded in
        // 'expected' results
        expected.setTool(rawToolResults.getToolName());
        expected.setToolVersion(rawToolResults.getToolVersion());

        // Return the modified expected as the actual.  Beware of the side effect!
        return expected;
    }

    /**
     * Check all actual results. If a real vulnerability matches, then exit. Otherwise keep going.
     *
     * @param exp The expected results
     * @param actList The list of actual results for this test case.
     * @return true if the expected result is found in the actual result (i.e., If True Positive,
     *     that results was found, If False Positive, that result was not found.)
     */
    private static boolean compare(TestCaseResult exp, List<TestCaseResult> actList, String tool) {
        // return true if there are no actual results and this was a false positive test
        if (actList == null || actList.isEmpty()) {
            return !exp.isTruePositive();
        }

        // otherwise check actual results
        for (TestCaseResult act : actList) {
            // Helpful in debugging
            // System.out.println( "  Evidence: " + act.getCWE() + " " + act.getEvidence() + "[" +
            // act.getConfidence() + "]");

            int actualCWE = act.getCWE();
            int expectedCWE = exp.getCWE();

            boolean match = actualCWE == expectedCWE;

            // Special case: many tools report CWE 89 (sqli) for Hibernate Injection (hqli) rather
            // than actual CWE of 564 So we accept either
            if (!match && (expectedCWE == 564)) {
                match = (actualCWE == 89);
            }

            // special hack since IBM/Veracode and CodeQL don't distinguish different kinds of weak
            // algorithm
            if (tool.startsWith("AppScan")
                    || tool.startsWith("Vera")
                    || tool.startsWith("CodeQL")) {
                if (expectedCWE == 328 && actualCWE == 327) {
                    match = true;
                }
            }

            // return true if we find an exact match for a True Positive test
            if (match) {
                return exp.isTruePositive();
            }
        }
        // if we couldn't find a match, then return true if it's a False Positive test
        return !exp.isTruePositive();
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
            System.out.println("ERROR: Can't find expected results file: " + file);
            System.exit(-1);
        } catch (IOException e) {
            System.out.println("ERROR: Reading contents of expected results file: " + file);
            e.printStackTrace();
            System.exit(-1);
        }

        return null;
    }

    /**
     * Generate all the vulnerability scorecards. And then 1 commercial tool average scorecard if
     * there are commercial tool results for at least 2 commercial tools. Also create the Tool
     * objects for: averageCommercialToolResults, averageNonCommercialToolResults,
     * overallAveToolResults.
     */
    private static void generateVulnerabilityScorecards(
            Set<Tool> tools,
            Set<String> catSet,
            File scoreCardDir,
            CommercialAveragesTable commercialAveragesTable) {

        // A side effect of this method is to calculate these averages
        averageCommercialToolResults = new HashMap<String, CategoryResults>();
        averageNonCommerciaToolResults = new HashMap<String, CategoryResults>();
        overallAveToolResults = new HashMap<String, CategoryResults>();

        final ClassLoader CL = BenchmarkScore.class.getClassLoader();

        VulnerabilityStatsTable vulnerabilityStatsTable =
                new VulnerabilityStatsTable(config, TESTSUITENAME, tools);

        for (String cat : catSet) {
            try {
                // Generate a comparison chart for all tools for this vuln category. When
                // constructed, scatter contains the Overall, Non-commercial, and Commercial stats
                // for this category across all tools.
                ScatterVulns scatter =
                        ScatterVulns.generateComparisonChart(
                                cat, tools, config.focus, scoreCardDir);

                // Before creating html for this vuln category, save the category level results into
                // averageCommercialToolResults, averageNonCommerciaToolResults,
                // overallAveToolResults
                BenchmarkScore.averageCommercialToolResults.put(
                        cat, scatter.getCommercialCategoryResults());
                BenchmarkScore.averageNonCommerciaToolResults.put(
                        cat, scatter.getNonCommercialCategoryResults());
                BenchmarkScore.overallAveToolResults.put(cat, scatter.getOverallCategoryResults());

                String filename =
                        TESTSUITENAME.simpleName()
                                + "_v"
                                + TESTSUITEVERSION
                                + "_Scorecard_for_"
                                + cat.replace(' ', '_');
                File htmlFile = new File(scoreCardDir, filename + ".html");

                // Resources in a jar file have to be loaded as streams. Not directly as Files.
                final String VULNTEMPLATERESOURCE = "scorecard/vulntemplate.html";
                InputStream vulnTemplateStream = CL.getResourceAsStream(VULNTEMPLATERESOURCE);
                if (vulnTemplateStream == null) {
                    System.out.println(
                            "ERROR - vulnTemplate stream is null for resource: "
                                    + VULNTEMPLATERESOURCE);
                }

                String html = IOUtils.toString(vulnTemplateStream, StandardCharsets.UTF_8);
                html = html.replace("${testsuite}", BenchmarkScore.TESTSUITENAME.fullName());
                String fullTitle =
                        BenchmarkScore.TESTSUITENAME.fullName() + " Scorecard for " + cat;

                html = html.replace("${image}", filename + ".png");
                html = html.replace("${title}", fullTitle);
                html =
                        html.replace(
                                "${vulnerability}",
                                cat + " (CWE #" + BenchmarkScore.translateNameToCWE(cat) + ")");
                html = html.replace("${version}", TESTSUITEVERSION);
                html = html.replace("${projectlink}", config.report.html.projectLinkEntry);

                html = html.replace("${table}", vulnerabilityStatsTable.generateFor(cat));
                html = html.replace("${tprlabel}", config.tprLabel);
                html =
                        html.replace(
                                "${precisionkey}",
                                config.report.html.precisionKeyEntry
                                        + config.report.html.fsCoreEntry);

                Files.write(htmlFile.toPath(), html.getBytes());

                // Only build commercial stats scorecard if there are at 2+ commercial tools
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
                                        + commercialAveragesTable.filename());
                // Resources in a jar file have to be loaded as streams. Not directly as Files.
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
        } // end if
    }
}
