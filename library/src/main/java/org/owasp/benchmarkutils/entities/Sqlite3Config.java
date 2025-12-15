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
 * @author David Anderson
 * @created 2024
 */
package org.owasp.benchmarkutils.entities;

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

    public void close() throws TestCaseSetupException {
        // Do nothing
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
