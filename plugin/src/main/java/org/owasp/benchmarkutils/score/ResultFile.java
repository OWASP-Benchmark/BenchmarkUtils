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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

public class ResultFile {
    private final byte[] rawContent;
    private final String filename;
    private final File originalFile;
    private JSONObject contentAsJson;
    private Document contentAsXml;
    // This is a special stream only set by test cases, because they are resource files, not actual
    // files on the file system. It is only used by the extract() method to pull files out of ZIP
    // archives in test case. The normal code pulls the data out of the result file.
    InputStream streamToFile = null; // If null, not used.

    public ResultFile(File fileToParse) throws IOException {
        this(fileToParse, readFileContent(fileToParse));
    }

    public ResultFile(String filename, String content) throws IOException {
        this(filename, content.getBytes());
    }

    public ResultFile(String filename, byte[] rawContent) throws IOException {
        this(new File(filename), rawContent);
    }

    public ResultFile(File fileToParse, byte[] rawContent) throws IOException {
        this.rawContent = rawContent;
        this.originalFile = fileToParse;
        this.filename = originalFile.getName();
        parseJson();
        parseXml();
    }

    private String removeBom(byte[] rawContent) {
        String s = new String(rawContent, StandardCharsets.UTF_8);

        if (s.startsWith("\uFEFF")) {
            return s.substring(1);
        }

        return s;
    }

    private static byte[] readFileContent(File fileToParse) throws IOException {
        return Files.readAllBytes(Paths.get(fileToParse.getPath()));
    }

    private void parseJson() {
        try {
            contentAsJson = new JSONObject(removeBom(rawContent));
        } catch (Exception ignored) {
            // No JSON
        }
    }

    private void parseXml() {
        try {
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            // Prevent XXE = Note, disabling DTDs entirely breaks the parsing of some XML files,
            // like a Burp results file, so have to use the alternate defense.
            // dbFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            docBuilderFactory.setFeature(
                    "http://xml.org/sax/features/external-general-entities", false);
            docBuilderFactory.setFeature(
                    "http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
            docBuilder.setErrorHandler(new DefaultHandler());
            InputSource is = new InputSource(new StringReader(this.content()));
            this.contentAsXml = docBuilder.parse(is);
        } catch (Exception ignored) {
            // No XML
        }
    }

    public String filename() {
        return filename;
    }

    public boolean isJson() {
        return contentAsJson != null;
    }

    public boolean isXml() {
        return contentAsXml != null;
    }

    public JSONObject json() {
        return contentAsJson;
    }

    public String content() {
        return removeBom(rawContent);
    }

    public File file() {
        return originalFile;
    }

    public CSVParser csvRecords() {
        return csvRecords(content());
    }

    private static CSVParser csvRecords(String content) {
        try {
            return CSVFormat.DEFAULT
                    .builder()
                    .setHeader()
                    .setSkipHeaderRecord(false)
                    .setIgnoreEmptyLines(false)
                    .build()
                    .parse(new StringReader(content));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public CSVParser csvRecordsSkipFirstRows(int skipRows) {
        List<String> rows = contentAsRows();

        return csvRecords(String.join("\n", rows.subList(skipRows, rows.size())));
    }

    public List<String> contentAsRows() {
        return Arrays.asList(content().split("\n"));
    }

    /**
     * Read the specified line of the provided file. Returns empty string if the given file does not
     * have as many lines.
     */
    public String line(int lineNum) {
        List<String> lines = Arrays.asList(removeBom(rawContent).split("\n"));

        if (lineNum >= lines.size()) {
            return "";
        }

        return lines.get(lineNum);
    }

    public List<String> lines() {
        return new ArrayList<>();
    }

    public Document xml() {
        return contentAsXml;
    }

    public Element xmlRootNode() {
        return xml().getDocumentElement();
    }

    public String xmlRootNodeName() {
        return isXml() ? xmlRootNode().getNodeName() : "";
    }

    /**
     * Finds the specified file in the zip file associated with this ResultFile, and returns an
     * InputStream to the specified file.
     *
     * @return An InputStream to the specified file.
     */
    public InputStream extract(String zipPath) {
        try {
            ZipInputStream zipIn;
            // Check to see if a stream to the file was set by a test case. If so, use that instead
            // of the File reference.
            if (this.streamToFile != null) zipIn = new ZipInputStream(this.streamToFile);
            else zipIn = new ZipInputStream(new FileInputStream(this.originalFile));

            ZipEntry entry = zipIn.getNextEntry();
            while (entry != null) {
                if (entry.getName().equals(zipPath)) {
                    // NOTE: Previously this method used to call another method that extracted the
                    // file into a new ResultFile with just the ZIP file attached to it. However,
                    // for VERY large Fortify files, you couldn't create a byte[] big enough to hold
                    // the entire file (as its was > 2GB), so you got an OutOfMemoryError. So now we
                    // return a Stream instead, and that gets passed to the DOM Parser directly,
                    // which works fine for large files.
                    return zipIn;
                }
                zipIn.closeEntry();
                entry = zipIn.getNextEntry();
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        throw new RuntimeException("ZipFile does not contain " + zipPath);
    }
}
