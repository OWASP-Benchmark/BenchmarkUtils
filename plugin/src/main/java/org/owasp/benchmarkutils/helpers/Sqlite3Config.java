package org.owasp.benchmarkutils.helpers;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlAttribute;

public class Sqlite3Config extends TestCaseSetup {

    private String initializationScriptFile;

    private String scriptFile;

    public void executeScripts(String scriptFile) throws FileNotFoundException, IOException {
        // db parameters
        String url = "jdbc:sqlite:./benchmark.db";

        // create a connection to the database
        try (Connection conn = DriverManager.getConnection(url)) {

            System.out.println("Connection to SQLite has been established.");

            Statement statement = conn.createStatement();

            List<String> lines = new ArrayList<String>();
            try (BufferedReader reader = new BufferedReader(new FileReader(scriptFile))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    lines.add(line);
                }
            }

            for (String line : lines) {
                statement.execute(line);
            }

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public void initialize() throws FileNotFoundException, IOException {
        executeScripts(this.initializationScriptFile);
    }

    public void setup() throws TestCaseSetupException {
        try {
            initialize();
            executeScripts(getScriptFile());
        } catch (IOException e) {
            throw new TestCaseSetupException("Could not setup Sqlite3Config for test case", e);
        }
    }

    @XmlAttribute(name = "script")
    @NotNull
    public String getScriptFile() {
        return scriptFile;
    }

    public void setScriptFile(String scriptFile) {
        this.scriptFile = scriptFile;
    }
}
