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
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.PrintStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.List;
import java.util.Vector;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLContext;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.ParseException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
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

    public static final String RESOURCES_DIR =
            USERDIR
                    + "src"
                    + File.separator
                    + "main"
                    + File.separator
                    + "resources"
                    + File.separator;

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

    public static String getCookie(HttpServletRequest request, String paramName) {
        Cookie[] values = request.getCookies();
        String param = "none";
        if (paramName != null) {
            for (int i = 0; i < values.length; i++) {
                if (values[i].getName().equals(paramName)) {
                    param = values[i].getValue();
                    break; // break out of for loop when param found
                }
            }
        }
        return param;
    }

    public static String getParam(HttpServletRequest request, String paramName) {
        String param = request.getParameter(paramName);
        return param;
    }

    public static String getOSCommandString(String append) {

        String command = null;
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            command = "cmd.exe /c " + append + " ";
        } else {
            command = append + " ";
        }

        return command;
    }

    public static String getInsecureOSCommandString(ClassLoader classLoader) {
        String command = null;
        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            command = Utils.getFileFromClasspath("insecureCmd.bat", classLoader).getAbsolutePath();
        } else {
            command = Utils.getFileFromClasspath("insecureCmd.sh", classLoader).getAbsolutePath();
        }
        return command;
    }

    public static List<String> getOSCommandArray(String append) {

        ArrayList<String> cmds = new ArrayList<String>();

        String osName = System.getProperty("os.name");
        if (osName.indexOf("Windows") != -1) {
            cmds.add("cmd.exe");
            cmds.add("/c");
            if (append != null) {
                cmds.add(append);
            }
        } else {
            cmds.add("sh");
            cmds.add("-c");
            if (append != null) {
                cmds.add(append);
            }
        }

        return cmds;
    }

    public static File getFileFromClasspath(String fileName, ClassLoader classLoader) {
        URL url = classLoader.getResource(fileName);
        if (url != null) {
            try {
                return new File(url.toURI().getPath());
            } catch (URISyntaxException e) {
                System.out.println(
                        "The file '" + fileName + "' from the classpath cannot be loaded.");
                e.printStackTrace();
            }
        } else
            System.out.println("The file '" + fileName + "' from the classpath cannot be loaded.");
        return null;
    }

    public static List<String> getLinesFromFile(File file) {
        if (!file.exists()) {
            try {
                System.out.println("Can't find file to get lines from: " + file.getCanonicalFile());
            } catch (IOException e) {
                System.out.println("Can't find file to get lines from.");
                e.printStackTrace();
            }
            return null;
        }

        List<String> sourceLines = new ArrayList<String>();

        try (FileReader fr = new FileReader(file);
                BufferedReader br = new BufferedReader(fr); ) {
            String line;
            while ((line = br.readLine()) != null) {
                sourceLines.add(line);
            }
        } catch (Exception e) {
            try {
                System.out.println("Problem reading contents of file: " + file.getCanonicalFile());
            } catch (IOException e2) {
                System.out.println("Problem reading file to get lines from.");
                e2.printStackTrace();
            }
            e.printStackTrace();
        }

        return sourceLines;
    }

    public static List<String> getLinesFromFile(String filename) {
        return getLinesFromFile(new File(filename));
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

    public static boolean writeLineToFile(Path pathToFileDir, String completeName, String line) {
        boolean result = true;
        PrintStream os = null;
        try {
            Files.createDirectories(pathToFileDir);
            File f = new File(completeName);
            if (!f.exists()) {
                f.createNewFile();
            }
            FileOutputStream fos = new FileOutputStream(f, true);
            os = new PrintStream(fos);
            os.println(line);
        } catch (IOException e1) {
            result = false;
            e1.printStackTrace();
        } finally {
            os.close();
        }

        return result;
    }

    public static boolean deleteFile(String completeName) {
        boolean result = true;
        File f = new File(completeName);
        if (f.exists()) {
            try {
                f.delete();
            } catch (SecurityException e) {
                System.out.println("Can't delete file: " + completeName);
                result = false;
            }
        }
        return result;
    }

    /**
     * UNUSED METHOD!!! Why was it created? Parses all the XML in the provided InputStream to
     * generate a List of test case requests. If testing that case fails, add its failure to the
     * list of failed test cases. (Not sure about this aspect of what it does.)
     *
     * @param http The inputstream to parse the XML test case request from (e.g., contents of
     *     benchmark-crawler(or attack)-http.xml
     * @param failedTestCases A list of error messages, 1 for each test case that failed.
     * @return A List of TestCaseRequest objects based on the file contents.
     * @throws Exception
     */
    /*	private static List<AbstractTestCaseRequest> parseHttpFile(InputStream http, List<String> failedTestCases) {

    		Node root = null;
    		DocumentBuilder newCrawlerBuilder = null;
    		try {
    			DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
    			InputSource is = new InputSource(http);
    			Document doc = docBuilder.parse(is);
    			root = doc.getDocumentElement();

    			newCrawlerBuilder = docBuilderFactory.newDocumentBuilder();
    		} catch (ParserConfigurationException e) {
    			System.out.println("ERROR: Problem creating new DocumentBuilder");
    			e.printStackTrace();
    			System.exit(-1);
    		} catch (IOException | SAXException e2) {
    			System.out.println("ERROR: Parsing XML input file.");
    			e2.printStackTrace();
    			System.exit(-1);
    		}

    		Document newCrawlerDoc = newCrawlerBuilder.newDocument();
    		Element newCrawlerRootElement = newCrawlerDoc.createElement("benchmarkSuite");
    		newCrawlerDoc.appendChild(newCrawlerRootElement);

    		List<AbstractTestCaseRequest> requests = new ArrayList<AbstractTestCaseRequest>();
    		List<Node> tests = XMLCrawler.getNamedChildren("benchmarkTest", root);
    		// TODO: What does this loop do? Figure out, and document here, and in javadoc for this method.
    		for (Node test : tests) {
    			String URL = XMLCrawler.getAttributeValue("URL", test).trim();
    			// ToDo: don't use 18 (instead calculate length of TESTCASE_NAME and # digits
    			if (failedTestCases
    					.contains(URL.substring(URL.indexOf(BenchmarkScore.TESTCASENAME),
    							URL.indexOf(BenchmarkScore.TESTCASENAME) + 18))) {
    				requests.add(parseHttpTest(test));
    				Node newNode = test.cloneNode(true);
    				newCrawlerDoc.adoptNode(newNode);
    				newCrawlerDoc.getDocumentElement().appendChild(newNode);
    			} else {
    				// The test case passed
    			}
    		}

    		// TODO: What is this delete for??
    		String failedTCFile = DATA_DIR + "benchmark-failed-http.xml";
    		File file = new File(failedTCFile);
    		if (file.exists()) {
    			if (file.delete()) {
    				// System.out.println("Crawler file " + fileName + " deleted.");
    			}
    		}

    		TransformerFactory transformerFactory = TransformerFactory.newInstance();
    		try {
    			Transformer transformer = transformerFactory.newTransformer();
    			DOMSource source = new DOMSource(newCrawlerDoc);

    			StreamResult result = new StreamResult(failedTCFile);

    			// Output to console for testing
    			// StreamResult result = new StreamResult(System.out);

    			transformer.transform(source, result);
    		} catch (TransformerException e) {
    			// System.out.println("Problem closing Crawler XML file: " +
    			// fileName);
    			e.printStackTrace();
    		}

    		return requests;
    	}
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
        boolean isVulnerability =
                Boolean.valueOf(XMLCrawler.getAttributeValue("tcVulnerable", test));

        List<Node> headerNodes = XMLCrawler.getNamedChildren("header", test);
        List<NameValuePair> headers = parseNameValuePairs(headerNodes);

        List<Node> cookieNodes = XMLCrawler.getNamedChildren("cookie", test);
        List<NameValuePair> cookies = parseNameValuePairs(cookieNodes);

        List<Node> getParamNodes = XMLCrawler.getNamedChildren("getparam", test);
        List<NameValuePair> getParams = parseNameValuePairs(getParamNodes);

        List<Node> formParamsNodes = XMLCrawler.getNamedChildren("formparam", test);
        List<NameValuePair> formParams = parseNameValuePairs(formParamsNodes);

        List<Node> payloadNodes = XMLCrawler.getNamedChildren("payload", test);
        if (payloadNodes.size() > 1)
            throw new TestCaseRequestFileParseException(
                    "There cannot be multiple payloads for a request");
        String payload = XMLCrawler.getAttributeValue("value", payloadNodes.get(0));

        switch (tcType) {
            case SERVLET:
                request =
                        new ServletTestCaseRequest(
                                url,
                                tcType,
                                category,
                                payload,
                                name,
                                uiTemplateFile,
                                templateFile,
                                sourceFile,
                                sourceUIType,
                                dataflowFile,
                                sinkFile,
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
                                payload,
                                name,
                                uiTemplateFile,
                                templateFile,
                                sourceFile,
                                sourceUIType,
                                dataflowFile,
                                sinkFile,
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
                                payload,
                                name,
                                uiTemplateFile,
                                templateFile,
                                sourceFile,
                                sourceUIType,
                                dataflowFile,
                                sinkFile,
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

    private static List<NameValuePair> parseNameValuePairs(List<Node> nodes)
            throws TestCaseRequestFileParseException {
        List<NameValuePair> nameValuePairs = new Vector<NameValuePair>();

        for (Node nameValuePairNode : nodes) {
            String name = XMLCrawler.getAttributeValue("name", nameValuePairNode);
            String value = XMLCrawler.getAttributeValue("value", nameValuePairNode);
            nameValuePairs.add(new BasicNameValuePair(name, value));
        }

        return nameValuePairs;
    }

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

    /*
     * A utility method used by the generated Java Cipher test cases.
     */
    private static javax.crypto.Cipher cipher = null;

    public static Cipher getCipher() {
        if (cipher == null) {
            try {
                cipher =
                        javax.crypto.Cipher.getInstance(
                                "RSA/ECB/OAEPWithSHA-512AndMGF1Padding", "SunJCE");
                // Prepare the cipher to encrypt
                java.security.KeyPairGenerator keyGen =
                        java.security.KeyPairGenerator.getInstance("RSA");
                keyGen.initialize(4096);
                java.security.PublicKey publicKey = keyGen.genKeyPair().getPublic();
                cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, publicKey);
            } catch (NoSuchAlgorithmException
                    | NoSuchProviderException
                    | NoSuchPaddingException
                    | InvalidKeyException e) {
                e.printStackTrace();
            }
        }
        return cipher;
    }

    public static SSLConnectionSocketFactory getSSLFactory() throws Exception {
        SSLContext sslcontext =
                SSLContexts.custom().loadTrustMaterial(null, new TrustSelfSignedStrategy()).build();
        // Allow TLSv1 protocol only
        SSLConnectionSocketFactory sslsf =
                new SSLConnectionSocketFactory(
                        sslcontext, new String[] {"TLSv1"}, null, NoopHostnameVerifier.INSTANCE);
        return sslsf;
    }

    public static void printRequestBase(HttpRequestBase request) {
        System.out.println(request.toString());
        for (Header header : request.getAllHeaders()) {
            System.out.println(header.getName() + " : " + header.getValue());
        }
        HttpEntity entity = ((HttpPost) request).getEntity();

        try {
            System.out.println(EntityUtils.toString(entity));
        } catch (ParseException | IOException e) {
            e.printStackTrace();
        }
    }
}
