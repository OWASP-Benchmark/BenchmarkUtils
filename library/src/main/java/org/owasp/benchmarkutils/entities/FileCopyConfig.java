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

import com.google.common.io.Files;
import java.io.File;
import java.io.IOException;
import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlAttribute;

public class FileCopyConfig extends TestCaseSetup {

    private String sourceFile;

    private String destinationFile;

    public void setup() throws TestCaseSetupException {
        try {
            Files.copy(new File(sourceFile), new File(destinationFile));
        } catch (IOException e) {
            throw new TestCaseSetupException("Could not setup HttpClientConfig for test case", e);
        }
    }

    public void close() throws TestCaseSetupException {
        // Do nothing
    }

    @XmlAttribute(name = "source", required = true)
    @NotNull
    public String getSourceFile() {
        return sourceFile;
    }

    public void setSourceFile(String sourceFile) {
        this.sourceFile = sourceFile;
    }

    @XmlAttribute(name = "destination", required = true)
    @NotNull
    public String getDestinationFile() {
        return destinationFile;
    }

    public void setDestinationFile(String destinationFile) {
        this.destinationFile = destinationFile;
    }
}
