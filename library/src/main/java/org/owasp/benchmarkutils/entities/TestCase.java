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

import java.util.Comparator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.eclipse.persistence.oxm.annotations.XmlPath;
import org.eclipse.persistence.oxm.annotations.XmlPaths;
import org.owasp.benchmarkutils.helpers.Category;
import org.owasp.benchmarkutils.helpers.CategoryAdapter;

public class TestCase {

    private Category category;

    private String dataflowFile;

    private String name;

    private int number;

    private String notAutoverifiableReason;

    private String sinkFile;

    private String sourceFile;

    private String sourceUIType;

    private String templateFile;

    private String type;

    private String UITemplateFile;

    private boolean isVulnerability;

    private String attackSuccessString;

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

    // FIXME: These fields are not in the crawler config file, but they need to be captured when
    // running the verification crawler because we retrieve request details from them to write to
    // failedTestCases.txt.
    //    private TestCaseRequest attackTestCaseRequest;
    //    private TestCaseRequest safeTestCaseRequest;

    static final Pattern lastIntPattern = Pattern.compile("[^0-9]+([0-9]+)$");

    public TestCase() {
        super();
    }

    // @XmlAttribute(name = "tcCategory", required = true)
    @XmlAttribute(name = "Category", required = true)
    @XmlJavaTypeAdapter(CategoryAdapter.class)
    @NotNull
    public Category getCategory() {
        return category;
    }

    public void setCategory(Category category) {
        this.category = category;
    }

    public void setDataflowFile(String dataflowFile) {
        this.dataflowFile = dataflowFile;
    }

    public void setNotAutoverifiableReason(String notAutoverifiableReason) {
        this.notAutoverifiableReason = notAutoverifiableReason;
    }

    public void setSinkFile(String sinkFile) {
        this.sinkFile = sinkFile;
    }

    public void setSourceFile(String sourceFile) {
        this.sourceFile = sourceFile;
    }

    public void setSourceUIType(String sourceUIType) {
        this.sourceUIType = sourceUIType;
    }

    public void setTemplateFile(String templateFile) {
        this.templateFile = templateFile;
    }

    public void setUITemplateFile(String uITemplateFile) {
        UITemplateFile = uITemplateFile;
    }

    public void setVulnerability(boolean isVulnerability) {
        this.isVulnerability = isVulnerability;
    }

    public void setAttackSuccessString(String attackSuccessString) {
        this.attackSuccessString = attackSuccessString;
    }

    // @XmlAttribute(name = "tcDataflowFile", required = true)
    @XmlAttribute(name = "DataflowFile", required = true)
    @NotNull
    public String getDataflowFile() {
        return dataflowFile;
    }

    // @XmlAttribute(name = "tcName", required = true)
    @XmlAttribute(name = "Name", required = true)
    @NotNull
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;

        // Auto extract the test case number from the name.
        Matcher matcher = lastIntPattern.matcher(name);
        if (matcher.find()) {
            String someNumberStr = matcher.group(1);
            this.number = Integer.parseInt(someNumberStr);
        } else {
            System.out.println(
                    "Warning: TestCaseRequest.setName() invoked with test case name: "
                            + name
                            + " that doesn't end with a test case number.");
        }
    }

    public int getNumber() {
        return number;
    }

    // @XmlAttribute(name = "tcNotAutoverifiable")
    @XmlAttribute(name = "NotAutoverifiable")
    public String getNotAutoverifiableReason() {
        return notAutoverifiableReason;
    }

    // @XmlAttribute(name = "tcSinkFile", required = true)
    @XmlAttribute(name = "SinkFile", required = true)
    @NotNull
    public String getSinkFile() {
        return sinkFile;
    }

    // @XmlAttribute(name = "tcSourceFile", required = true)
    @XmlAttribute(name = "SourceFile", required = true)
    @NotNull
    public String getSourceFile() {
        return sourceFile;
    }

    // @XmlAttribute(name = "tcSourceUIType", required = true)
    @XmlAttribute(name = "SourceUIType", required = true)
    @NotNull
    public String getSourceUIType() {
        return sourceUIType;
    }

    // @XmlAttribute(name = "tcTemplateFile", required = true)
    @XmlAttribute(name = "TemplateFile", required = true)
    @NotNull
    public String getTemplateFile() {
        return templateFile;
    }

    // @XmlAttribute(name = "tcUITemplateFile", required = true)
    @XmlAttribute(name = "UITemplateFile", required = true)
    @NotNull
    public String getUITemplateFile() {
        return UITemplateFile;
    }

    //    @XmlAttribute(name = "tcType", required = true)
    //    @XmlReadOnly
    //    @NotNull
    //    public String getType() {
    //        return type;
    //    }

    // @XmlAttribute(name = "tcAttackSuccess")
    @XmlAttribute(name = "AttackSuccess")
    public String getAttackSuccessString() {
        return this.attackSuccessString;
    }

    // @XmlAttribute(name = "tcVulnerable", required = true)
    @XmlAttribute(name = "Vulnerability", required = true)
    public boolean isVulnerability() {
        return isVulnerability;
    }

    @XmlElement(name = "Input", required = true)
    public TestCaseInput getTestCaseInput() {
        return testCaseInput;
    }

    //    public getTestCaseExecutor() {
    //
    //    }

    public boolean isUnverifiable() {
        return getNotAutoverifiableReason() != null;
    }

    //    public TestCaseRequest getAttackTestCaseRequest() {
    //        return attackTestCaseRequest;
    //    }
    //
    //    public void setAttackTestCaseRequest(TestCaseRequest attackTestCaseRequest) {
    //        this.attackTestCaseRequest = attackTestCaseRequest;
    //    }
    //
    //    public TestCaseRequest getSafeTestCaseRequest() {
    //        return safeTestCaseRequest;
    //    }
    //
    //    public void setSafeTestCaseRequest(TestCaseRequest safeTestCaseRequest) {
    //        this.safeTestCaseRequest = safeTestCaseRequest;
    //    }

    public void setTestCaseInput(TestCaseInput testCaseInput) {
        this.testCaseInput = testCaseInput;
    }

    public TestCaseSetup getTestCaseSetup() {
        return testCaseSetup;
    }

    public void setTestCaseSetup(TestCaseSetup testCaseSetup) {
        this.testCaseSetup = testCaseSetup;
    }

    //	public void execute() {
    //
    //        this.getTestCaseInput().execute(this.getName());
    //    }
    //
    //    // FIXME: Maybe not a good idea to move this here
    //    public void executeAndVerify() {
    //    	TestCaseInput testCaseInput = getTestCaseInput();
    //
    //    	if (testCaseInput instanceof HttpTestCaseInput) {
    //    		HttpTestCaseInput httpTestCaseInput = (HttpTestCaseInput) testCaseInput;
    //	        HttpUriRequest attackRequest = httpTestCaseInput.buildAttackRequest();
    //	        HttpUriRequest safeRequest = httpTestCaseInput.buildSafeRequest();
    //
    //	        // Send the next test case request with its attack payload
    //	        ResponseInfo attackPayloadResponseInfo = sendRequest(httpclient, attackRequest);
    //	        responseInfoList.add(attackPayloadResponseInfo);
    //
    //	        // Log the response
    //	        log(attackPayloadResponseInfo);
    //
    //	        ResponseInfo safePayloadResponseInfo = null;
    //	        if (!isUnverifiable()) {
    //	            // Send the next test case request with its safe payload
    //	            safePayloadResponseInfo = sendRequest(httpclient, safeRequest);
    //	            responseInfoList.add(safePayloadResponseInfo);
    //
    //	            // Log the response
    //	            log(safePayloadResponseInfo);
    //	        }
    //
    //	        TestCaseVerificationResults result =
    //	                new TestCaseVerificationResults(
    //	                        attackRequest,
    //	                        safeRequest,
    //	                        this,
    //	                        attackPayloadResponseInfo,
    //	                        safePayloadResponseInfo);
    //	        results.add(result);
    //    	}
    //
    //        // Verify the response
    //        if (RegressionTesting.isTestingEnabled) {
    //            handleResponse(result);
    //        }
    //    }

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
                + ", isVulnerability="
                + isVulnerability
                + ", "
                + testCaseInput
                + "]";
    }

    public static Comparator<TestCase> getNameComparator() {
        return new Comparator<TestCase>() {

            @Override
            public int compare(TestCase o1, TestCase o2) {
                if (!o1.name.equalsIgnoreCase(o2.name)) return o1.name.compareTo(o2.name);
                return 0;
            }
        };
    }
}
