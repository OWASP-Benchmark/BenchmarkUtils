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
 * @author Nick Sanidas
 * @created 2015
 */
package org.owasp.benchmarkutils.helpers;

import static java.nio.file.StandardOpenOption.APPEND;
import static java.nio.file.StandardOpenOption.CREATE;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystem;
import java.nio.file.FileSystemNotFoundException;
import java.nio.file.FileSystems;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.tools.AbstractTestCaseRequest;
import org.owasp.benchmarkutils.tools.AbstractTestCaseRequest.TestCaseType;
import org.owasp.benchmarkutils.tools.JerseyTestCaseRequest;
import org.owasp.benchmarkutils.tools.ServletTestCaseRequest;
import org.owasp.benchmarkutils.tools.SpringTestCaseRequest;
import org.owasp.benchmarkutils.tools.XMLCrawler;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class Utils {

    // Properties used by the generated test suite

    public static final String USERDIR = System.getProperty("user.dir") + File.separator;

    public static final String DATA_DIR = USERDIR + "data" + File.separator;

    private static final DocumentBuilderFactory safeDocBuilderFactory =
            DocumentBuilderFactory.newInstance();

    static {
        try {
            // Make DBF safe from XXE by disabling doctype declarations (per OWASP XXE cheat sheet)
            safeDocBuilderFactory.setFeature(
                    "http://apache.org/xml/features/disallow-doctype-decl", true);
        } catch (ParserConfigurationException e) {
            System.out.println(
                    "ERROR: couldn't set http://apache.org/xml/features/disallow-doctype-decl");
            e.printStackTrace();
        }
    }

    /**
     * Find the specified file on the class path and return a File handle to it. Note: If the
     * specified file is inside of a JAR on the classpath, this method will throw an error or return
     * null, as you can't return a File object for something inside a JAR. You need to instead
     * return a Stream for that resource.
     *
     * @param fileName The file to retrieve
     * @param classLoader The classloader to use
     * @return A File object referencing the specified file, if found. Otherwise null.
     */
    public static File getFileFromClasspath(String filePath, ClassLoader classLoader) {

        URL url = classLoader.getResource(filePath);
        if (url != null) {
            try {
                System.out.printf("getFileFromClasspath() url is: %s%n", url);
                URI resourceURI = url.toURI();
                String externalFormURI = url.toExternalForm();
                System.out.printf(
                        "getFileFromClasspath() url.toURI() is: %s and external form is: %s%n",
                        resourceURI, externalFormURI);
                //                String filePath = resourceURI.getPath();
                //                System.out.println("getFileFromClasspath() url.toURI().getPath()
                // is: " + filePath);
                //                if (resourceURI != null) return new File(resourceURI);
                if (externalFormURI != null) return new File(externalFormURI);
                else {
                    System.out.printf(
                            "The path for the resource: '%s' with URI: %s is null for some reason."
                                    + " So can't load that resource as a file.%n",
                            filePath, resourceURI);

                    return null;
                }
            } catch (URISyntaxException e) {
                System.out.printf(
                        "The path for the resource: '%s' can't be computed due to the following error:%n",
                        filePath);
                e.printStackTrace();
            }
        } else System.out.printf("The file '%s' from the classpath cannot be loaded.%n", filePath);
        return null;
    }

    /**
     * Read the given text file and return the contents.
     *
     * @param file The file to read
     * @return The file contents
     */
    public static List<String> getLinesFromFile(File file) {
        if (file == null) {
            System.out.println("ERROR: getLinesFromFile() invoked with null file parameter.");
            return null;
        }
        String filename = file.getName();
        try {
            try {
                filename = file.getCanonicalPath();
            } catch (IOException e) {
                // Do nothing, thus using default getName() value.
            }
            return getLinesFromStream(new FileInputStream(file), filename);
        } catch (FileNotFoundException e) {
            System.out.println("Can't find file to get lines from: " + filename);
            return null;
        }
    }

    /**
     * Read the given text file and return the contents.
     *
     * @param filePath The file to read
     * @return The file contents
     */
    public static List<String> getLinesFromFile(String filePath) {
        return getLinesFromFile(new File(filePath));
    }

    public static List<String> getLinesFromStream(InputStream fileStream, String sourceFileName) {

        List<String> sourceLines = new ArrayList<String>();

        try (BufferedReader br = new BufferedReader(new InputStreamReader(fileStream))) {
            String line;
            while ((line = br.readLine()) != null) {
                sourceLines.add(line);
            }
        } catch (Exception e) {
            System.out.println("Problem reading contents of file stream: " + sourceFileName);
            e.printStackTrace();
        }

        return sourceLines;
    }

    /**
     * Write a single String to the specified file.
     *
     * @param file - The path to the target file.
     * @param content - The content to write.
     * @param append - True to append to an existing file. False to create or overwrite the file.
     * @throws IOException
     */
    public static void writeToFile(Path file, String content, boolean append) throws IOException {
        PrintStream os = new PrintStream(Files.newOutputStream(file, append ? APPEND : CREATE));
        os.println(content);
    }

    /**
     * Write a list of Strings to the specified file.
     *
     * @param file - The path to the target file.
     * @param content - The list of Strings to write out.
     * @param append - True to append to an existing file. False to create or overwrite the file.
     * @throws IOException
     */
    public static void writeToFile(Path file, List<String> contentLines, boolean append)
            throws IOException {
        PrintStream os = new PrintStream(Files.newOutputStream(file, append ? APPEND : CREATE));

        for (String line : contentLines) {
            os.println(line);
        }
    }

    /**
     * Load a list of requests for a generated test suite from the given file.
     *
     * @param file The file to parse
     * @return A list of requests
     * @throws TestCaseRequestFileParseException
     */
    public static List<AbstractTestCaseRequest> parseHttpFile(File file)
            throws TestCaseRequestFileParseException {
        List<AbstractTestCaseRequest> requests = new ArrayList<AbstractTestCaseRequest>();

        try {
            FileInputStream inputStream = new FileInputStream(file);
            DocumentBuilder docBuilder = safeDocBuilderFactory.newDocumentBuilder();
            InputSource is = new InputSource(inputStream);
            Document doc = docBuilder.parse(is);
            Node root = doc.getDocumentElement();

            // Side effect: Set the test suite name and version # for global use
            BenchmarkScore.TESTSUITE = XMLCrawler.getAttributeValue("testsuite", root);
            BenchmarkScore.TESTSUITEVERSION = XMLCrawler.getAttributeValue("version", root);

            List<Node> tests = XMLCrawler.getNamedChildren("benchmarkTest", root);
            for (Node test : tests) {
                AbstractTestCaseRequest request = parseHttpTest(test);
                requests.add(request);
            }
        } catch (ParserConfigurationException | SAXException | IOException e) {
            throw new TestCaseRequestFileParseException("Error during parsing", e);
        }
        return requests;
    }

    /**
     * Load a single test case request from the given XML document node.
     *
     * @param test The node to parse
     * @return A test case request
     * @throws TestCaseRequestFileParseException
     */
    public static AbstractTestCaseRequest parseHttpTest(Node test)
            throws TestCaseRequestFileParseException {
        AbstractTestCaseRequest request = null;

        String url = XMLCrawler.getAttributeValue("URL", test);
        TestCaseType tcType = TestCaseType.valueOf(XMLCrawler.getAttributeValue("tcType", test));
        String category = XMLCrawler.getAttributeValue("tcCategory", test);
        String name = XMLCrawler.getAttributeValue("tcName", test);
        String uiTemplateFile = XMLCrawler.getAttributeValue("tcUITemplateFile", test);
        String templateFile = XMLCrawler.getAttributeValue("tcTemplateFile", test);
        String sourceFile = XMLCrawler.getAttributeValue("tcSourceFile", test);
        String sourceUIType = XMLCrawler.getAttributeValue("tsSourceUIType", test);
        String dataflowFile = XMLCrawler.getAttributeValue("tcDataflowFile", test);
        String sinkFile = XMLCrawler.getAttributeValue("tcSinkFile", test);
        String attackSuccessString = XMLCrawler.getAttributeValue("tcAttackSuccess", test);
        String unverifiableReason = XMLCrawler.getAttributeValue("tcNotAutoverifiable", test);
        boolean isUnverifiable = (unverifiableReason != null);
        boolean isVulnerability =
                Boolean.valueOf(XMLCrawler.getAttributeValue("tcVulnerable", test));

        List<Node> headerNodes = XMLCrawler.getNamedChildren("header", test);
        List<RequestVariable> headers = parseRequestVariables(headerNodes);

        List<Node> cookieNodes = XMLCrawler.getNamedChildren("cookie", test);
        List<RequestVariable> cookies = parseRequestVariables(cookieNodes);

        List<Node> getParamNodes = XMLCrawler.getNamedChildren("getparam", test);
        List<RequestVariable> getParams = parseRequestVariables(getParamNodes);

        List<Node> formParamsNodes = XMLCrawler.getNamedChildren("formparam", test);
        List<RequestVariable> formParams = parseRequestVariables(formParamsNodes);

        switch (tcType) {
            case SERVLET:
                request =
                        new ServletTestCaseRequest(
                                url,
                                tcType,
                                category,
                                name,
                                uiTemplateFile,
                                templateFile,
                                sourceFile,
                                sourceUIType,
                                dataflowFile,
                                sinkFile,
                                isUnverifiable,
                                isVulnerability,
                                attackSuccessString,
                                headers,
                                cookies,
                                getParams,
                                formParams);
                break;
            case SPRINGWS:
                request =
                        new SpringTestCaseRequest(
                                url,
                                tcType,
                                category,
                                name,
                                uiTemplateFile,
                                templateFile,
                                sourceFile,
                                sourceUIType,
                                dataflowFile,
                                sinkFile,
                                isUnverifiable,
                                isVulnerability,
                                attackSuccessString,
                                headers,
                                cookies,
                                getParams,
                                formParams);
                break;
            case JERSEYWS:
                request =
                        new JerseyTestCaseRequest(
                                url,
                                tcType,
                                category,
                                name,
                                uiTemplateFile,
                                templateFile,
                                sourceFile,
                                sourceUIType,
                                dataflowFile,
                                sinkFile,
                                isUnverifiable,
                                isVulnerability,
                                attackSuccessString,
                                headers,
                                cookies,
                                getParams,
                                formParams);
                break;
            default:
                throw new TestCaseRequestFileParseException("Unrecognized tcType: " + tcType);
        }

        return request;
    }

    /**
     * Load all request variables (get params, post params, headers, and cookies) from the given
     * list of XML document nodes.
     *
     * @param nodes The nodes to parse
     * @return A list of request variables
     * @throws TestCaseRequestFileParseException
     */
    private static List<RequestVariable> parseRequestVariables(List<Node> nodes)
            throws TestCaseRequestFileParseException {
        List<RequestVariable> requestVariables = new ArrayList<>();
        for (Node requestVariableNode : nodes) {
            String name = XMLCrawler.getAttributeValue("name", requestVariableNode);
            String value = XMLCrawler.getAttributeValue("value", requestVariableNode);
            String attackName = XMLCrawler.getAttributeValue("attackName", requestVariableNode);
            ;
            String attackValue = XMLCrawler.getAttributeValue("attackValue", requestVariableNode);
            ;
            String safeName = XMLCrawler.getAttributeValue("safeName", requestVariableNode);
            String safeValue = XMLCrawler.getAttributeValue("safeValue", requestVariableNode);
            requestVariables.add(
                    new RequestVariable(name, value, attackName, attackValue, safeName, safeValue));
        }

        return requestVariables;
    }

    /**
     * A utility method to read all the lines out of a CSV file that indicate failed test cases.
     *
     * @param csvFile The file to read.
     * @return A List of all the lines in the .csv that indicate a test case failure.
     */
    public static List<String> readCSVFailedTC(String csvFile) {
        String line = "";
        String cvsSplitBy = ",";
        List<String> csv = new ArrayList<String>();
        String[] tempLine;

        try (BufferedReader br = new BufferedReader(new FileReader(csvFile))) {
            while ((line = br.readLine()) != null) {
                tempLine = line.split(cvsSplitBy);
                if (tempLine[5].trim().equalsIgnoreCase("fail")) {
                    csv.add(tempLine[0]);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return csv;
    }

    // from: https://stackoverflow.com/questions/1386809/copy-directory-from-a-jar-file
    // answer by: lpiepiora.  Example usage:
    // copyFromJar("/path/to/the/dir/in/jar", Paths.get("/tmp/from-jar"))
    // Modified by DRW to handle individual source files, not just directories

    /**
     * This method copies all the files starting at source, to target. Source can be a file or
     * directory on the filesystem, or a file or directory inside a JAR file.
     *
     * @param source the file or directory to start copying from
     * @param target the destination directory
     */
    public static void copyFilesFromDirRecursively(String source, final Path target) {

        // In case the caller provides a trailing /
        if (source.endsWith("/")) source = source.substring(0, source.length() - 1);
        final String sourceLoc = source;

        final ClassLoader CL = Utils.class.getClassLoader();
        final URL srcURL = CL.getResource(sourceLoc);

        if (srcURL == null) {
            System.out.printf(
                    "ERROR: copyFilesFromDirRecursively() can't find source resource: %s%n",
                    sourceLoc);
            return;
        }

        if (srcURL.getProtocol().equals("file")) {
            // Copy the files from one directory to another using the normal
            // FileUtils.copyDirectory() method

            File sourceFile;
            try {
                sourceFile = Paths.get(srcURL.toURI()).toFile();
            } catch (URISyntaxException e1) {
                // This should never happen since CL.getResource() found it
                e1.printStackTrace();
                return;
            }
            if (sourceFile.exists())
                if (sourceFile.isDirectory())
                    try {
                        FileUtils.copyDirectory(sourceFile, target.toFile(), false);
                    } catch (IOException e) {
                        System.out.println("ERROR: couldn't copyDirectory()");
                        e.printStackTrace();
                    }
                else
                    // Simply copy file to target dir
                    try {
                        Files.copy(
                                sourceFile.toPath(),
                                Paths.get(target.toString(), sourceFile.getName()),
                                StandardCopyOption.REPLACE_EXISTING);
                    } catch (IOException e) {
                        System.out.println("ERROR: couldn't copy source file to target directory,");
                        e.printStackTrace();
                    }
            else
                System.out.printf(
                        "ERROR: copyFilesFromDirRecursively() can't find source File: %s%n",
                        sourceLoc);

            return; // File(s) copied or it failed
        }

        if (!srcURL.getProtocol().equals("jar")) {
            System.out.printf(
                    "ERROR: source resource not a file: or jar: resource. It is: %s%n", srcURL);
            return;
        }

        // Copy the files out of the JAR to the target dir using the stackoverflow
        // copy-directory-from-a-jar-file solution
        URI resource;
        try {
            //            resource = CL.getResource("").toURI();
            resource = CL.getResource(sourceLoc).toURI();
        } catch (URISyntaxException e2) {
            System.out.printf("ERROR: couldn't find resource: %s%n", sourceLoc);
            e2.printStackTrace();
            return;
        }

        FileSystem fileSystem;
        try {
            // If the target location already exists, use it.
            fileSystem = FileSystems.getFileSystem(resource);
        } catch (FileSystemNotFoundException e) {
            try {
                // Otherwise create it
                fileSystem =
                        FileSystems.newFileSystem(resource, Collections.<String, String>emptyMap());
            } catch (IOException e1) {
                e1.printStackTrace();
                return;
            }
        }

        // The following is done to calculate whether the sourceLoc is a file or directory
        // This is needed later in visitFile() to calculate the properly replacement path
        // when copying a single file, rather than a directory of files.
        String jarSource = sourceLoc; // Default location

        URL jarURL = Utils.class.getProtectionDomain().getCodeSource().getLocation();
        try {
            JarFile myJar = new JarFile(new File(jarURL.toURI()));
            JarEntry entry = myJar.getJarEntry(sourceLoc);
            if (entry == null) {
                System.out.printf("ERROR: Target resource file: '%s' can't be found%n", sourceLoc);
                return;
            } else if (!entry.isDirectory()) {
                // IF the source is not a directory, we use the directory containing the file as
                // the jarPath
                int slashLoc = sourceLoc.lastIndexOf('/');
                if (slashLoc == -1)
                    slashLoc = 0; // In case there is no containing directory. TODO: UNTESTED
                jarSource = sourceLoc.substring(0, slashLoc);
            }
        } catch (IOException | URISyntaxException e) {
            System.out.printf(
                    "ERROR trying to determine if: '%s' is a file or directory.%n", sourceLoc);
            e.printStackTrace();
            return;
        }
        final String jarSourcePath = jarSource;

        Path jarPath = fileSystem.getPath("/" + sourceLoc);

        try {
            Files.walkFileTree(
                    jarPath,
                    new SimpleFileVisitor<Path>() {

                        @Override
                        public FileVisitResult preVisitDirectory(
                                Path dir, BasicFileAttributes attrs) throws IOException {
                            Files.createDirectories(
                                    target.resolve(jarPath.relativize(dir).toString()));
                            return FileVisitResult.CONTINUE;
                        }

                        @Override
                        public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                                throws IOException {
                            String targetLoc = file.toString().substring(1);
                            targetLoc = targetLoc.replace(jarSourcePath, target.toString());
                            Path targetPath = new File(targetLoc).toPath();
                            Files.copy(file, targetPath, StandardCopyOption.REPLACE_EXISTING);
                            return FileVisitResult.CONTINUE;
                        }
                    });
        } catch (IOException e) {
            System.out.println("ERROR trying to copy resources from JAR file to file system.");
            e.printStackTrace();
        }
    }
}
