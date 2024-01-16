package org.owasp.benchmarkutils.helpers;

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
