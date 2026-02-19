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
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.eclipse.persistence.oxm.annotations.XmlPath;
import org.eclipse.persistence.oxm.annotations.XmlPaths;
import org.owasp.benchmarkutils.helpers.Category;
import org.owasp.benchmarkutils.helpers.CategoryAdapter;

@XmlRootElement(name = "TestCase")
public class TestCase {

    private Category category;
    private String name; // Full name of the test case
    private int number; // The number of this test case

    private boolean isVulnerability;

    private String sourceFile;
    private String sourceUIType;
    private String dataflowFile = "none";
    private String sinkFile;

    private String templateFile;
    private String UITemplateFile;

    private String notAutoverifiableReason; // Any value, e.g. "none" sets it notAutoverifiable

    private String verificationResult = "notYetKnown";

    private TestCaseInput testCaseInput;
    private String attackSuccessString;

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
    //    private TestExecutor safeTestExecutor;
    //    private TestExecutor attackTestExecutor;

    static final Pattern lastIntPattern = Pattern.compile("[^0-9]+([0-9]+)$");

    public TestCase() {
        super();
    }

    @XmlAttribute(name = "AttackSuccessIndicator")
    public String getAttackSuccessString() {
        return this.attackSuccessString;
    }

    @XmlAttribute(name = "Category", required = true)
    @XmlJavaTypeAdapter(CategoryAdapter.class)
    @NotNull
    public Category getCategory() {
        return category;
    }

    @XmlAttribute(name = "DataflowFile", required = true)
    @NotNull
    public String getDataflowFile() {
        return dataflowFile;
    }

    @XmlAttribute(name = "Name", required = true)
    @NotNull
    public String getName() {
        return name;
    }

    public int getNumber() {
        return number;
    }

    @XmlAttribute(name = "NotAutoverifiable")
    public String getNotAutoverifiableReason() {
        return notAutoverifiableReason;
    }

    @XmlAttribute(name = "SinkFile", required = true)
    @NotNull
    public String getSinkFile() {
        return sinkFile;
    }

    @XmlAttribute(name = "SourceFile", required = true)
    @NotNull
    public String getSourceFile() {
        return sourceFile;
    }

    @XmlAttribute(name = "SourceUIType", required = true)
    @NotNull
    public String getSourceUIType() {
        return sourceUIType;
    }

    @XmlAttribute(name = "TemplateFile", required = true)
    @NotNull
    public String getTemplateFile() {
        return templateFile;
    }

    @XmlAttribute(name = "UITemplateFile", required = true)
    @NotNull
    public String getUITemplateFile() {
        return UITemplateFile;
    }

    @XmlElement(name = "Input", required = true)
    public TestCaseInput getTestCaseInput() {
        return testCaseInput;
    }

    public TestCaseSetup getTestCaseSetup() {
        return testCaseSetup;
    }

    public boolean isUnverifiable() {
        return getNotAutoverifiableReason() != null;
    }

    @XmlAttribute(name = "Vulnerability", required = true)
    public boolean isVulnerability() {
        return isVulnerability;
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

    public void setAttackSuccessString(String attackSuccessString) {
        this.attackSuccessString = attackSuccessString;
    }

    public void setCategory(Category category) {
        this.category = category;
    }

    public void setDataflowFile(String dataflowFile) {
        this.dataflowFile = dataflowFile;
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

    public void setTestCaseInput(TestCaseInput testCaseInput) {
        this.testCaseInput = testCaseInput;
    }

    public void setUITemplateFile(String uITemplateFile) {
        UITemplateFile = uITemplateFile;
    }

    public void setVulnerability(boolean isVulnerability) {
        this.isVulnerability = isVulnerability;
    }

    public void setVerificationResult(String result) {
        this.verificationResult = result;
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

    @XmlElement(name = "VerificationResult", required = true)
    public String getVerificationResult() {
        return this.verificationResult;
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
