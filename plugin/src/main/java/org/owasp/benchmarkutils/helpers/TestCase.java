package org.owasp.benchmarkutils.helpers;

import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.eclipse.persistence.oxm.annotations.XmlPath;
import org.eclipse.persistence.oxm.annotations.XmlPaths;
import org.eclipse.persistence.oxm.annotations.XmlReadOnly;

@XmlRootElement
public class TestCase {

    private Category category;

    private String dataflowFile;

    private String name;

    private String notAutoverifiableReason;

    private String sinkFile;

    private String sourceFile;

    private String sourceUIType;

    private String templateFile;

    private String type;

    private String UITemplateFile;

    private boolean isVulnerable;

    private TestCaseInput testCaseInput;

    @XmlElements({
        @XmlElement(type = HttpClientConfig.class),
        @XmlElement(type = FileCopyConfig.class),
        @XmlElement(type = Sqlite3Config.class)
    })
    @XmlPaths({
        @XmlPath("fee[@type='HttpClientConfig']"),
        @XmlPath("fee[@type='FileCopyConfig']"),
        @XmlPath("fee[@type='Sqlite3Config']")
    })
    private TestCaseSetup testCaseSetup;

    private TestCaseRequest attackTestCaseRequest;

    private TestCaseRequest safeTestCaseRequest;

    @XmlAttribute(name = "tcCategory", required = true)
    @XmlJavaTypeAdapter(CategoryAdapter.class)
    @NotNull
    public Category getCategory() {
        return category;
    }

    @XmlAttribute(name = "tcDataflowFile", required = true)
    @NotNull
    public String getDataflowFile() {
        return dataflowFile;
    }

    @XmlAttribute(name = "tcName", required = true)
    @NotNull
    public String getName() {
        return name;
    }

    @XmlAttribute(name = "tcNotAutoverifiable")
    public String getNotAutoverifiableReason() {
        return notAutoverifiableReason;
    }

    @XmlAttribute(name = "tcSinkFile", required = true)
    @NotNull
    public String getSinkFile() {
        return sinkFile;
    }

    @XmlAttribute(name = "tcSourceFile", required = true)
    @NotNull
    public String getSourceFile() {
        return sourceFile;
    }

    @XmlAttribute(name = "tcSourceUIType", required = true)
    @NotNull
    public String getSourceUIType() {
        return sourceUIType;
    }

    @XmlAttribute(name = "tcTemplateFile", required = true)
    @NotNull
    public String getTemplateFile() {
        return templateFile;
    }

    @XmlAttribute(name = "tcUITemplateFile", required = true)
    @NotNull
    public String getUITemplateFile() {
        return UITemplateFile;
    }

    @XmlAttribute(name = "tcType", required = true)
    @XmlReadOnly
    @NotNull
    public String getType() {
        return type;
    }

    @XmlAttribute(name = "tcVulnerable", required = true)
    public boolean isVulnerable() {
        return isVulnerable;
    }

    @XmlElement(name = "input", required = true)
    public TestCaseInput getTestCaseInput() {
        return testCaseInput;
    }

    public TestCaseRequest getAttackTestCaseRequest() {
        return attackTestCaseRequest;
    }

    public void setAttackTestCaseRequest(TestCaseRequest attackTestCaseRequest) {
        this.attackTestCaseRequest = attackTestCaseRequest;
    }

    public TestCaseRequest getSafeTestCaseRequest() {
        return safeTestCaseRequest;
    }

    public void setSafeTestCaseRequest(TestCaseRequest safeTestCaseRequest) {
        this.safeTestCaseRequest = safeTestCaseRequest;
    }

    public void setTestCaseInput(TestCaseInput testCaseInput) {
        this.testCaseInput = testCaseInput;
    }

    public void execute() {

        this.getTestCaseInput().execute(this.getName());
    }

    @Override
    public String toString() {
        return "TestCase ["
                + "category="
                + category
                + ", dataflowFile="
                + dataflowFile
                + ", name="
                + name
                + ", notAutoverifiableReason="
                + notAutoverifiableReason
                + ", sinkFile="
                + sinkFile
                + ", sourceFile="
                + sourceFile
                + ", sourceUIType="
                + sourceUIType
                + ", templateFile="
                + templateFile
                + ", UITemplateFile="
                + UITemplateFile
                + ", isVulnerable="
                + isVulnerable
                + ", "
                + testCaseInput
                + "]";
    }
}
