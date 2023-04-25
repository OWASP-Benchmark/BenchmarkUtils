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
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.text.DecimalFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import org.owasp.benchmarkutils.helpers.Categories;
import org.owasp.benchmarkutils.helpers.Category;
import org.owasp.benchmarkutils.helpers.Utils;
import org.owasp.benchmarkutils.score.parsers.Reader;
import org.owasp.benchmarkutils.score.report.ScatterHome;
import org.owasp.benchmarkutils.score.report.ScatterInterpretation;
import org.owasp.benchmarkutils.score.report.ScatterVulns;
import org.xml.sax.SAXException;

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
    public static String TESTSUITE; // Pulled from expected results file
    public static final String TEST = "Test";
    public static String TESTCASENAME; // Set w/TESTSUITE. i.e., TESTSUITE + TEST;

    public static String TESTPACKAGE = "org.owasp.benchmark.testcode.";

    // The # of numbers in a test case name. Must match what is actually generated.
    public static final int TESTIDLENGTH = 5;

    private static final String GUIDEFILENAME = "Scorecard_Guide.html";
    private static final String HOMEFILENAME = "Scorecard_Home.html";
    // scorecard dir normally created under current user directory
    public static final String SCORECARDDIRNAME = "scorecard";

    // The name of this file if generated. This value is calculated by code below. Not set via
    // config.
    private static String commercialAveScorecardFilename = null;

    // The values stored in this is pulled from the categories.xml config file
    //    public static Categories CATEGORIES;

    // This is the default project link. This is set to "" if includeProjectLink set to false.
    // TODO: Make this value configurable via .yaml file
    public static String PROJECTLINKENTRY =
            "            <p>\n"
                    + "                For more information, please visit the <a href=\"https://owasp.org/www-project-benchmark/\">OWASP Benchmark Project Site</a>.\n"
                    + "            </p>\n";

    // This is the Key Entry for Precision, which is added to the Key for tables that include
    // Precision. If includePrecision explicitly set to false via .yaml, then this default value set
    // to "".
    public static String PRECISIONKEYENTRY =
            "<tr>\n"
                    + "                    <th>Precision = TP / ( TP + FP )</th>\n"
                    + "                    <td>The percentage of reported vulnerabilities that are true positives. Defined at <a href=\"https://en.wikipedia.org/wiki/Precision_and_recall\">Wikipedia</a>.</td>\n"
                    + "                </tr>\n";

    // This is the Key Entry for F-Score, which is added to the Key for tables that also include
    // Precision. If includePrecision explicitly set to false via .yaml, then this default value set
    // to "".
    public static String FSCOREKEYENTRY =
            "<tr>\n"
                    + "                    <th>F-score = 2 * Precision * Recall / (Precision + Recall)</th>\n"
                    + "                    <td>The harmonic mean of the precision and recall. A value of 1.0 indicates perfect precision and recall. Defined at <a href=\"https://en.wikipedia.org/wiki/F-score\">Wikipedia</a>.</td>\n"
                    + "                </tr>\n";

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

        // TODO: move to html class (once this has been extracted, too)
        if (!config.includeProjectLink) {
            PROJECTLINKENTRY = "";
        }

        if (!config.includePrecision) {
            // These two values are both included or not included together (currently)
            PRECISIONKEYENTRY = "";
            FSCOREKEYENTRY = "";
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

        // Load in the categories definitions from the config file.
        try {
            InputStream categoriesFileStream =
                    BenchmarkScore.class.getClassLoader().getResourceAsStream(Categories.FILENAME);
            new Categories(categoriesFileStream);
        } catch (ParserConfigurationException | SAXException | IOException e1) {
            System.out.println("ERROR: couldn't load categories from categories config file.");
            e1.printStackTrace();
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

                        // Step 5a: Go through each result file, score the tool, and generate a
                        // scorecard for that tool
                        if (!config.anonymousMode) {
                            for (File actual : rootDirFile.listFiles()) {
                                // Don't confuse the expected results file as an actual results file
                                // if its in the same directory
                                if (!actual.isDirectory()
                                        && !expectedResultsFilename.equals(actual.getName())) {
                                    // process() populates tools with the supplied tool's results
                                    process(actual, expectedResults, tools, scoreCardDir);
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
                                    process(actual, expectedResults, tools, scoreCardDir);
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
                                process(actual, expectedResults, tools, scoreCardDir);
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
                                process(actual, expectedResults, tools, scoreCardDir);
                            }
                        }
                    } // end else (!anonymousMode)

                } else {
                    // This will process a single results file, if that is what the 2nd parameter
                    // points to. This has never been used.
                    // process() populates tools with the supplied tool's results
                    process(resultsFileOrDir, expectedResults, tools, scoreCardDir);
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
        BenchmarkScore.generateVulnerabilityScorecards(tools, catSet, scoreCardDir);
        System.out.println("Vulnerability scorecards computed.");

        // Step 7: Generate the tool scorecards now that the overall Vulnerability scorecards and
        // stats have been calculated
        for (Tool tool : tools) {
            tool.generateScorecard(overallAveToolResults, scoreCardDir);
        }

        // Step 8: Update all the menus for all the generated pages to reflect the tools and
        // vulnerability categories
        updateMenus(tools, catSet, scoreCardDir);

        // Step 9: Generate the overall comparison chart for all the tools in this test
        ScatterHome.generateComparisonChart(tools, config.focus, scoreCardDir);

        // Step 10: Generate the results table across all the tools in this test
        String table = generateOverallStatsTable(tools);

        try {
            String html = new String(Files.readAllBytes(homeFilePath));
            html = html.replace("${projectlink}", BenchmarkScore.PROJECTLINKENTRY);
            html = html.replace("${table}", table);
            html = html.replace("${tprlabel}", config.tprLabel);
            html =
                    html.replace(
                            "${precisionkey}",
                            BenchmarkScore.PRECISIONKEYENTRY + BenchmarkScore.FSCOREKEYENTRY);
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

        System.out.println(BenchmarkScore.TESTSUITE + " scorecards complete.");

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
     * @param scoreCardDir - The directory where the scorecard is being written to.
     */
    private static void process(
            File rawToolResultsFile,
            TestSuiteResults expectedResults,
            Set<Tool> tools,
            File scoreCardDir) {

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
                    actualResultsFileName = produceResultsFile(actualResults, scoreCardDir);
                }

                Map<String, TP_FN_TN_FP_Counts> scores = calculateScores(actualResults);

                ToolResults metrics = calculateMetrics(scores);
                metrics.setScanTime(rawToolResults.getTime());

                // This has the side effect of also generating the tool's report in the
                // scoreCardDir.
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
            if (tcr.isReal() && tcr.isPassed()) c.tp++; // tp
            else if (tcr.isReal() && !tcr.isPassed()) c.fn++; // fn

            // fake vulnerabilities
            else if (!tcr.isReal() && tcr.isPassed()) c.tn++; // tn
            else if (!tcr.isReal() && !tcr.isPassed()) c.fp++; // fp
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
            // System.out.println( tc + ", " + exp.getCategory() + ", " + exp.isReal() + ", " +
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
            return !exp.isReal();
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

            // special hack since IBM/Veracode don't distinguish different kinds of weak algorithm
            if (tool.startsWith("AppScan") || tool.startsWith("Vera")) {
                if (expectedCWE == 328 && actualCWE == 327) {
                    match = true;
                }
            }

            // return true if we find an exact match for a True Positive test
            if (match) {
                return exp.isReal();
            }
        }
        // if we couldn't find a match, then return true if it's a False Positive test
        return !exp.isReal();
    }

    // Create a TestResults object that contains the expected results for this version
    // of the test suite.
    private static TestSuiteResults readExpectedResults(File file) {
        TestSuiteResults tr = new TestSuiteResults("Expected", true, null);

        try (final BufferedReader fr = new BufferedReader(new FileReader(file))) {
            // Read the 1st line. Parse out the test suite name and version #, which looks like:
            // # test name, category, real vulnerability, cwe, TESTSUITENAME version: x.y,
            // YYYY-MM-DD

            String line = fr.readLine();
            final String TESTSUITE_VERSION_PREFIX = " version: ";
            if (line != null) {
                String[] firstLineElements = line.split(", ");
                int startOfVersionStringLocation =
                        firstLineElements[4].indexOf(TESTSUITE_VERSION_PREFIX);
                if (startOfVersionStringLocation != -1) {
                    final String TESTSUITENAME =
                            firstLineElements[4].substring(0, startOfVersionStringLocation);
                    tr.setTestSuiteName(TESTSUITENAME);
                    BenchmarkScore.TESTSUITE = TESTSUITENAME; // Set classwide variable
                    BenchmarkScore.TESTCASENAME = // Set classwide variable;
                            TESTSUITENAME + TEST;
                    startOfVersionStringLocation += TESTSUITE_VERSION_PREFIX.length();
                } else {
                    String versionNumError =
                            "Couldn't find "
                                    + TESTSUITE_VERSION_PREFIX
                                    + " on first line of expected results file";
                    System.out.println(versionNumError);
                    throw new IOException(versionNumError);
                }
                // Trim off everything except the version #
                line = firstLineElements[4].substring(startOfVersionStringLocation);
                tr.setTestSuiteVersion(line);
            }

            boolean reading = true;
            while (reading) {
                line = fr.readLine();
                reading = line != null;
                if (reading) {
                    // Normally, each line contains: test name, category, real vulnerability, cwe #

                    // String[] parts = line.split(",");
                    // regex from
                    // http://stackoverflow.com/questions/1757065/java-splitting-a-comma-separated-string-but-ignoring-commas-in-quotes
                    // This regex needed because some 'full details' entries contain comma's inside
                    // quoted strings
                    String[] parts = line.split(",(?=([^\"]*\"[^\"]*\")*[^\"]*$)");
                    if (parts[0] != null && parts[0].startsWith(TESTCASENAME)) {
                        TestCaseResult tcr = new TestCaseResult();
                        tcr.setTestCaseName(parts[0]);
                        tcr.setCategory(parts[1]);
                        tcr.setReal(Boolean.parseBoolean(parts[2]));
                        tcr.setCWE(Integer.parseInt(parts[3]));

                        tcr.setNumber(Reader.testNumber(parts[0]));

                        // Handle situation where expected results has full details
                        // Sometimes, it also has: source, data flow, data flow filename, sink

                        if (parts.length > 4) {
                            tcr.setSource(parts[4]);
                            tcr.setDataFlow(parts[5]);
                            // tcr.setDataFlowFile(parts[6]);
                            tcr.setSink(parts[6]);
                        }

                        tr.put(tcr);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            System.out.println("ERROR: Can't find expected results file: " + file);
            System.exit(-1);
        } catch (IOException e) {
            System.out.println("ERROR: Reading contents of expected results file: " + file);
            e.printStackTrace();
            System.exit(-1);
        }
        return tr;
    }

    /**
     * This produces the .csv of all the results for this tool. It's basically the expected results
     * file with a couple of extra columns in it to say what the actual result for this tool was per
     * test case and whether that result was a pass or fail.
     *
     * @param actual The actual TestResults to produce the actual results file for.
     * @return The name of the results file produced
     */
    private static String produceResultsFile(TestSuiteResults actual, File scoreCardDir) {

        String testSuiteVersion = actual.getTestSuiteVersion();
        String resultsFileName =
                scoreCardDir.getAbsolutePath()
                        + File.separator
                        + TESTSUITE
                        + "_v"
                        + testSuiteVersion
                        + "_Scorecard_for_"
                        + actual.getToolNameAndVersion().replace(' ', '_')
                        + ".csv";
        File resultsFile = new File(resultsFileName);
        try (FileOutputStream fos = new FileOutputStream(resultsFile, false);
                PrintStream ps = new PrintStream(fos); ) {

            Set<Integer> testCaseKeys = actual.keySet();

            boolean fulldetails =
                    (actual.get(testCaseKeys.iterator().next()).get(0).getSource() != null);

            // Write actual results header
            ps.print("# test name, category, CWE, ");
            if (fulldetails) ps.print("source, data flow, sink, ");
            ps.print(
                    "real vulnerability, identified by tool, pass/fail, "
                            + TESTSUITE
                            + " version: "
                            + testSuiteVersion);

            // Append the date YYYY-MM-DD to the header in each .csv file
            Calendar c = Calendar.getInstance();
            String s = String.format("%1$tY-%1$tm-%1$te", c);
            ps.println(", Actual results generated: " + s);

            for (Integer expectedResultsKey : testCaseKeys) {
                // Write meta data to file here.
                TestCaseResult actualResult = actual.get(expectedResultsKey.intValue()).get(0);
                ps.print(actualResult.getName());
                ps.print(", " + actualResult.getCategory());
                ps.print(", " + actualResult.getCWE());
                if (fulldetails) {
                    ps.print("," + actualResult.getSource());
                    ps.print("," + actualResult.getDataFlow());
                    ps.print("," + actualResult.getSink());
                }
                boolean isreal = actualResult.isReal();
                ps.print(", " + isreal);
                boolean passed = actualResult.isPassed();
                boolean toolresult = !(isreal ^ passed);
                ps.print(", " + toolresult);
                ps.println(", " + (passed ? "pass" : "fail"));
            }

            System.out.println("Actual results file generated: " + resultsFile.getAbsolutePath());

            return resultsFile.getName();

        } catch (FileNotFoundException e) {
            System.out.println(
                    "ERROR: Can't create actual results file: " + resultsFile.getAbsolutePath());
        } catch (IOException e1) {
            e1.printStackTrace();
        }

        return null; // Should have returned results file name earlier if successful
    }

    /**
     * Generate all the vulnerability scorecards. And then 1 commercial tool average scorecard if
     * there are commercial tool results for at least 2 commercial tools. Also create the Tool
     * objects for: averageCommercialToolResults, averageNonCommercialToolResults,
     * overallAveToolResults.
     */
    private static void generateVulnerabilityScorecards(
            Set<Tool> tools, Set<String> catSet, File scoreCardDir) {
        StringBuilder htmlForCommercialAverages = null;

        int commercialToolTotal = 0;
        int numberOfVulnCategories = 0;
        int commercialLowTotal = 0;
        int commercialAveTotal = 0;
        int commercialHighTotal = 0;

        // A side effect of this method is to calculate these averages
        averageCommercialToolResults = new HashMap<String, CategoryResults>();
        averageNonCommerciaToolResults = new HashMap<String, CategoryResults>();
        overallAveToolResults = new HashMap<String, CategoryResults>();

        final ClassLoader CL = BenchmarkScore.class.getClassLoader();

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
                        TESTSUITE
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
                html =
                        html.replace(
                                "${testsuite}",
                                BenchmarkScore.fullTestSuiteName(BenchmarkScore.TESTSUITE));
                String fullTitle =
                        BenchmarkScore.fullTestSuiteName(BenchmarkScore.TESTSUITE)
                                + " Scorecard for "
                                + cat;

                html = html.replace("${image}", filename + ".png");
                html = html.replace("${title}", fullTitle);
                html =
                        html.replace(
                                "${vulnerability}",
                                cat + " (CWE #" + BenchmarkScore.translateNameToCWE(cat) + ")");
                html = html.replace("${version}", TESTSUITEVERSION);
                html = html.replace("${projectlink}", BenchmarkScore.PROJECTLINKENTRY);

                String table = generateVulnStatsTable(tools, cat);
                html = html.replace("${table}", table);
                html = html.replace("${tprlabel}", config.tprLabel);
                html =
                        html.replace(
                                "${precisionkey}",
                                BenchmarkScore.PRECISIONKEYENTRY + BenchmarkScore.FSCOREKEYENTRY);

                Files.write(htmlFile.toPath(), html.getBytes());

                // Now build up the commercial stats scorecard if there are at 2+ commercial tools
                if (scatter.getCommercialToolCount() > 1) {
                    if (htmlForCommercialAverages == null) {
                        commercialToolTotal = scatter.getCommercialToolCount();
                        htmlForCommercialAverages = new StringBuilder();
                        htmlForCommercialAverages.append("<table class=\"table\">\n");
                        htmlForCommercialAverages.append("<tr>");
                        htmlForCommercialAverages.append("<th>Vulnerability Category</th>");
                        htmlForCommercialAverages.append("<th>Low Tool Type</th>");
                        htmlForCommercialAverages.append("<th>Low Score</th>");
                        htmlForCommercialAverages.append("<th>Ave Score</th>");
                        htmlForCommercialAverages.append("<th>High Score</th>");
                        htmlForCommercialAverages.append("<th>High Tool Type</th>");
                        htmlForCommercialAverages.append("</tr>\n");
                    } // if 1st time through

                    numberOfVulnCategories++;

                    String style = "";
                    htmlForCommercialAverages.append("<tr>");
                    htmlForCommercialAverages.append("<td>" + cat + "</td>");
                    htmlForCommercialAverages.append(
                            "<td>" + scatter.getCommercialLowToolType() + "</td>");
                    if (scatter.getCommercialLow() <= 10) style = "class=\"danger\"";
                    else if (scatter.getCommercialLow() >= 50) style = "class=\"success\"";
                    htmlForCommercialAverages.append(
                            "<td " + style + ">" + scatter.getCommercialLow() + "</td>");
                    commercialLowTotal += scatter.getCommercialLow();
                    htmlForCommercialAverages.append("<td>" + scatter.getCommercialAve() + "</td>");
                    commercialAveTotal += scatter.getCommercialAve();
                    if (scatter.getCommercialHigh() <= 10) style = "class=\"danger\"";
                    else if (scatter.getCommercialHigh() >= 50) style = "class=\"success\"";
                    htmlForCommercialAverages.append(
                            "<td " + style + ">" + scatter.getCommercialHigh() + "</td>");
                    commercialHighTotal += scatter.getCommercialHigh();
                    htmlForCommercialAverages.append(
                            "<td>" + scatter.getCommercialHighToolType() + "</td>");
                    htmlForCommercialAverages.append("</tr>\n");
                } // if more than 1 commercial tool

            } catch (IOException e) {
                System.out.println("Error generating vulnerability summaries: " + e.getMessage());
                e.printStackTrace();
            }
        } // end for loop

        // if we computed a commercial average, then add the last row to the table AND create the
        // file and write the HTML to it.
        if (htmlForCommercialAverages != null) {

            htmlForCommercialAverages.append("<tr>");
            htmlForCommercialAverages.append(
                    "<td>Average across all categories for " + commercialToolTotal + " tools</td>");
            htmlForCommercialAverages.append("<td></td>");
            htmlForCommercialAverages.append(
                    "<td>"
                            + new DecimalFormat("0.0")
                                    .format(
                                            (float) commercialLowTotal
                                                    / (float) numberOfVulnCategories)
                            + "</td>");
            htmlForCommercialAverages.append(
                    "<td>"
                            + new DecimalFormat("0.0")
                                    .format(
                                            (float) commercialAveTotal
                                                    / (float) numberOfVulnCategories)
                            + "</td>");
            htmlForCommercialAverages.append(
                    "<td>"
                            + new DecimalFormat("0.0")
                                    .format(
                                            (float) commercialHighTotal
                                                    / (float) numberOfVulnCategories)
                            + "</td>");
            htmlForCommercialAverages.append("<td></td>");
            htmlForCommercialAverages.append("</tr>\n");
            htmlForCommercialAverages.append("</table>\n");

            try {
                commercialAveScorecardFilename =
                        TESTSUITE + "_v" + TESTSUITEVERSION + "_Scorecard_for_Commercial_Tools";
                Path htmlfile =
                        Paths.get(
                                scoreCardDir.getAbsolutePath()
                                        + File.separator
                                        + commercialAveScorecardFilename
                                        + ".html");
                // Resources in a jar file have to be loaded as streams. Not directly as Files.
                InputStream vulnTemplateStream =
                        CL.getResourceAsStream(scoreCardDir + "/commercialAveTemplate.html");
                String html = IOUtils.toString(vulnTemplateStream, StandardCharsets.UTF_8);
                html =
                        html.replace(
                                "${testsuite}",
                                BenchmarkScore.fullTestSuiteName(BenchmarkScore.TESTSUITE));
                html = html.replace("${version}", TESTSUITEVERSION);
                html = html.replace("${projectlink}", BenchmarkScore.PROJECTLINKENTRY);

                String table = htmlForCommercialAverages.toString();
                html = html.replace("${table}", table);
                html = html.replace("${tprlabel}", config.tprLabel);
                html =
                        html.replace(
                                "${precisionkey}",
                                BenchmarkScore.PRECISIONKEYENTRY + BenchmarkScore.FSCOREKEYENTRY);

                Files.write(htmlfile, html.getBytes());
                System.out.println("Commercial average scorecard computed.");
            } catch (IOException e) {
                System.out.println("Error generating commercial scorecard: " + e.getMessage());
                e.printStackTrace();
            }
        } // end if
    }

    /**
     * This generates the vulnerability stats table that goes at the bottom of each vulnerability
     * category page.
     *
     * @param tools - The set of all tools being scored. Each Tool includes it's scored results.
     * @param category - The vulnerability category to generate this table for.
     * @return The HTML of the vulnerability stats table.
     */
    private static String generateVulnStatsTable(Set<Tool> tools, String category) {
        StringBuilder sb = new StringBuilder();
        sb.append("<table class=\"table\">\n");
        sb.append("<tr>");
        sb.append("<th>Tool</th>");
        sb.append("<th>Type</th>");
        if (config.mixedMode) sb.append("<th>" + TESTSUITE + " Version</th>");
        sb.append("<th>TP</th>");
        sb.append("<th>FN</th>");
        sb.append("<th>TN</th>");
        sb.append("<th>FP</th>");
        sb.append("<th>Total</th>");
        if (config.includePrecision) sb.append("<th>Precision</th><th>F-score</th>");
        sb.append("<th>${tprlabel}</th>");
        sb.append("<th>FPR</th>");
        sb.append("<th>Score</th>");
        sb.append("</tr>\n");

        for (Tool tool : tools) {

            if (!(config.showAveOnlyMode && tool.isCommercial())) {
                ToolResults or = tool.getOverallResults();
                Map<String, TP_FN_TN_FP_Counts> scores = tool.getScores();
                TP_FN_TN_FP_Counts c = scores.get(category);
                CategoryResults r = or.getCategoryResults(category);
                String style = "";

                if (Math.abs(r.truePositiveRate - r.falsePositiveRate) < .1)
                    style = "class=\"danger\"";
                else if (r.truePositiveRate > .7 && r.falsePositiveRate < .3)
                    style = "class=\"success\"";
                sb.append("<tr " + style + ">");
                sb.append("<td>" + tool.getToolNameAndVersion() + "</td>");
                sb.append("<td>" + tool.getToolType() + "</td>");
                if (config.mixedMode) sb.append("<td>" + tool.getTestSuiteVersion() + "</td>");
                sb.append("<td>" + c.tp + "</td>");
                sb.append("<td>" + c.fn + "</td>");
                sb.append("<td>" + c.tn + "</td>");
                sb.append("<td>" + c.fp + "</td>");
                sb.append("<td>" + r.totalTestCases + "</td>");
                if (config.includePrecision) {
                    sb.append("<td>" + new DecimalFormat("#0.00%").format(r.precision) + "</td>");
                    sb.append("<td>" + new DecimalFormat("#0.0000").format(r.fscore) + "</td>");
                }
                sb.append(
                        "<td>" + new DecimalFormat("#0.00%").format(r.truePositiveRate) + "</td>");
                sb.append(
                        "<td>" + new DecimalFormat("#0.00%").format(r.falsePositiveRate) + "</td>");
                sb.append("<td>" + new DecimalFormat("#0.00%").format(r.score) + "</td>");
                sb.append("</tr>\n");
            }
        }

        sb.append("</table>");
        return sb.toString();
    }

    /**
     * Generate the overall stats table across all the tools for the bottom of the home page.
     *
     * @param tools - The set of all tools being scored. Each Tool includes it's scored results.
     * @return The HTML of the overall stats table.
     */
    private static String generateOverallStatsTable(Set<Tool> tools) {
        StringBuilder sb = new StringBuilder();
        sb.append("<table class=\"table\">\n");
        sb.append("<tr>");
        sb.append("<th>Tool</th>");
        if (config.mixedMode) sb.append("<th>" + TESTSUITE + " Version</th>");
        sb.append("<th>Type</th>");
        if (config.includePrecision) sb.append("<th>Precision*</th><th>F-score*</th>");
        sb.append("<th>${tprlabel}*</th>");
        sb.append("<th>FPR*</th>");
        sb.append("<th>Score*</th>");
        sb.append("</tr>\n");

        for (Tool tool : tools) {

            if (!(config.showAveOnlyMode && tool.isCommercial())) {
                ToolResults or = tool.getOverallResults();
                String style = "";

                if (Math.abs(or.getTruePositiveRate() - or.getFalsePositiveRate()) < .1)
                    style = "class=\"danger\"";
                else if (or.getTruePositiveRate() > .7 && or.getFalsePositiveRate() < .3)
                    style = "class=\"success\"";
                sb.append("<tr " + style + ">");
                sb.append("<td>" + tool.getToolNameAndVersion() + "</td>");
                if (config.mixedMode) sb.append("<td>" + tool.getTestSuiteVersion() + "</td>");
                sb.append("<td>" + tool.getToolType() + "</td>");
                if (config.includePrecision) {
                    sb.append(
                            "<td>"
                                    + new DecimalFormat("#0.00%").format(or.getPrecision())
                                    + "</td>");
                    sb.append(
                            "<td>" + new DecimalFormat("#0.0000").format(or.getFScore()) + "</td>");
                }
                sb.append(
                        "<td>"
                                + new DecimalFormat("#0.00%").format(or.getTruePositiveRate())
                                + "</td>");
                sb.append(
                        "<td>"
                                + new DecimalFormat("#0.00%").format(or.getFalsePositiveRate())
                                + "</td>");
                sb.append(
                        "<td>"
                                + new DecimalFormat("#0.00%").format(or.getOverallScore())
                                + "</td>");
                sb.append("</tr>\n");
            }
        }

        sb.append("</table>");
        sb.append(
                "<p>*-Please refer to each tool's scorecard for the data used to calculate these values.");

        return sb.toString();
    }

    /**
     * Updates the menus of all the scorecards previously generated so people can navigate between
     * all the tool results. Also perform a few other tag replacements for things that need to be
     * done in the final stages of scorecard generation.
     *
     * @param tools - All the scored tools.
     * @param catSet - The set of vulnerability categories to create menus for
     * @param scoreCardDir - The directory containing the HTML files to be updated.
     */
    private static void updateMenus(Set<Tool> tools, Set<String> catSet, File scoreCardDir) {

        // Create tool menu
        StringBuffer sb = new StringBuffer();
        for (Tool tool : tools) {
            if (!(config.showAveOnlyMode && tool.isCommercial())) {
                sb.append("<li><a href=\"");
                sb.append(tool.getScorecardFilename());
                sb.append(".html\">");
                sb.append(tool.getToolNameAndVersion());
                sb.append("</a></li>");
                sb.append(System.lineSeparator());
            }
        }

        // Before finishing, check to see if there is a commercial average scorecard file, and if so
        // Add it to the menu
        if (commercialAveScorecardFilename != null) {
            sb.append("<li><a href=\"");
            sb.append(commercialAveScorecardFilename);
            sb.append(".html\">");
            sb.append("Commercial Average");
            sb.append("</a></li>");
            sb.append(System.lineSeparator());
        }

        String toolmenu = sb.toString();

        // create vulnerability menu
        sb = new StringBuffer();
        for (String cat : catSet) {
            String filename =
                    TESTSUITE + "_v" + TESTSUITEVERSION + "_Scorecard_for_" + cat.replace(' ', '_');
            sb.append("            <li><a href=\"");
            sb.append(filename);
            sb.append(".html\">");
            sb.append(cat);
            sb.append("</a></li>");
            sb.append(System.lineSeparator());
        }
        String vulnmenu = sb.toString();

        // rewrite HTML files with new menus
        updateMenuTemplates(toolmenu, vulnmenu, scoreCardDir);
    }

    /*
     * This method goes through all the already generated .html files and updates their menus and a few other
     * things in those files.
     */
    private static void updateMenuTemplates(String toolmenu, String vulnmenu, File scoreCardDir) {
        for (File f : scoreCardDir.listFiles()) {
            if (!f.isDirectory() && f.getName().endsWith(".html")) {
                try {
                    String html = new String(Files.readAllBytes(f.toPath()));
                    html = html.replace("${toolmenu}", toolmenu);
                    html = html.replace("${vulnmenu}", vulnmenu);
                    html =
                            html.replace(
                                    "${testsuite}",
                                    BenchmarkScore.fullTestSuiteName(BenchmarkScore.TESTSUITE));
                    html = html.replace("${version}", TESTSUITEVERSION);
                    html = html.replace("${projectlink}", BenchmarkScore.PROJECTLINKENTRY);
                    html = html.replace("${cwecategoryname}", config.cweCategoryName);
                    html =
                            html.replace(
                                    "${precisionkey}",
                                    BenchmarkScore.PRECISIONKEYENTRY
                                            + BenchmarkScore.FSCOREKEYENTRY);

                    Files.write(f.toPath(), html.getBytes());
                } catch (IOException e) {
                    System.out.println("Error updating menus in: " + f.getName());
                    e.printStackTrace();
                }
            }
        }
    }

    // A utility method for providing a more descriptive test suite name than the base, single word,
    // test suite name.
    public static String fullTestSuiteName(String suite) {
        return ("Benchmark".equals(suite) ? "OWASP Benchmark" : suite);
    }
}
