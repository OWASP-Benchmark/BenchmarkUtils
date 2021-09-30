package org.owasp.benchmarkutils.score;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.json.JSONObject;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;
import org.xml.sax.helpers.DefaultHandler;

public class ResultFile {

    private final List<String> linesContent = new ArrayList<>();
    private final String rawContent;
    private final String filename;
    private final File originalFile;
    private JSONObject contentAsJson;
    private Document contentAsXml;

    public ResultFile(File fileToParse) throws IOException {
        readFileContent(fileToParse);
        originalFile = fileToParse;
        rawContent = String.join("", linesContent);
        filename = fileToParse.getName();
        parseJson();
        parseXml();
    }

    public ResultFile(String fileToParse, String content) throws IOException {
        rawContent = content;
        linesContent.addAll(Arrays.asList(content.split("\n")));
        originalFile = new File(fileToParse);
        filename = originalFile.getName();
        parseJson();
        parseXml();
    }

    private void readFileContent(File fileToParse) throws IOException {
        try (BufferedReader br = new BufferedReader(new FileReader(fileToParse))) {
            String line;
            while ((line = br.readLine()) != null) {
                linesContent.add(line);
            }
        }
    }

    private void parseJson() {
        try {
            contentAsJson = new JSONObject(rawContent);
        } catch (Exception ignored) {
            // No JSON
        }
    }

    private void parseXml() {
        try {
            DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
            // Prevent XXE = Note, disabling DTDs entirely breaks the parsing of some XML files,
            // like a
            // Burp results file, so have to use the alternate defense.
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

    public JSONObject json() {
        return contentAsJson;
    }

    public String content() {
        return rawContent;
    }

    public File file() {
        return originalFile;
    }

    /**
     * Read the specified line of the provided file. Returns empty string if the given file does not
     * have as many lines.
     */
    public String line(int lineNum) {
        if (lineNum >= linesContent.size()) {
            return "";
        }

        return linesContent.get(lineNum);
    }

    public List<String> lines() {
        return linesContent;
    }

    public Document xml() {
        return contentAsXml;
    }

    public Element xmlRootNode() {
        return xml().getDocumentElement();
    }

    public String xmlRootNodeName() {
        return xmlRootNode().getNodeName();
    }
}
