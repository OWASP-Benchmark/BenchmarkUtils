package org.owasp.benchmarkutils.score;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.json.JSONObject;

public class ResultFile {

    private final List<String> linesContent = new ArrayList<>();
    private final String rawContent;
    private final String filename;
    private final File originalFile;
    private JSONObject contentAsJson;

    public ResultFile(File fileToParse) throws IOException {
        readFileContent(fileToParse);
        originalFile = fileToParse;
        rawContent = String.join("", linesContent);
        filename = fileToParse.getName();
        parseJson();
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
     * Read the specified line of the provided file. If its blank, skip all blank lines until a
     * non-blank line is found and return that. Return "" if no non-blank line is found from the
     * specified line on.
     *
     * @return The first non-blank line in the file starting with the specified line. null if there
     *     aren't that many lines in the file.
     */
    public String line(int lineNum) {
        if (lineNum >= linesContent.size()) {
            return "";
        }

        return linesContent.get(lineNum);
    }
}
