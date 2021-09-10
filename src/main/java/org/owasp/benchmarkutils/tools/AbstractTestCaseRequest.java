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
 * PURPOSE. See the GNU General Public License for more details
 *
 * @author Juan Gama
 * @created 2017
 */
package org.owasp.benchmarkutils.tools;

import java.io.File;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import javax.validation.constraints.NotNull;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSeeAlso;
import javax.xml.bind.annotation.XmlTransient;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.methods.HttpUriRequest;
import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorNode;
import org.owasp.benchmarkutils.helpers.Category;
import org.owasp.benchmarkutils.helpers.CategoryAdapter;
import org.owasp.benchmarkutils.helpers.RequestVariable;

@XmlSeeAlso({
    ServletTestCaseRequest.class,
    JerseyTestCaseRequest.class,
    SpringTestCaseRequest.class
})
@XmlDiscriminatorNode("@tcType")
public abstract class AbstractTestCaseRequest {

    /*
     * The 1st three are Java.
     */
    public enum TestCaseType {
        JERSEYWS,
        SERVLET,
        SPRINGWS,
        NODEEXPRESS
    }

    public static Comparator<AbstractTestCaseRequest> getNameComparator() {
        return new Comparator<AbstractTestCaseRequest>() {

            @Override
            public int compare(AbstractTestCaseRequest o1, AbstractTestCaseRequest o2) {
                if (!o1.name.equalsIgnoreCase(o2.name)) return o1.name.compareTo(o2.name);
                return 0;
            }
        };
    }

    private Category category;
    private List<RequestVariable> cookies = new 
      <RequestVariable>();
    private String dataflowFile;
    private List<RequestVariable> formParams = new ArrayList<RequestVariable>();
    private String fullURL;
    private List<RequestVariable> getParams = new ArrayList<RequestVariable>();
    private List<RequestVariable> headers = new ArrayList<RequestVariable>();
    private String notAutoverifiableReason;
    private boolean isUnverifiable;
    private boolean isVulnerability;
    private String attackSuccessString;
    private String name;
    private String query;
    private String sinkFile;
    private String sourceFile;
    private String sourceUIType;
    private TestCaseType tcType;
    private String templateFile;
    private String uiTemplateFile;

    public AbstractTestCaseRequest() {}

    //    /**
    //     * This class contains enough information to generate an HttpUriRequest for a generated
    // test
    //     * case.
    //     *
    //     * @param fullURL
    //     * @param tcType
    //     * @param category
    //     * @param name
    //     * @param uiTemplateFile
    //     * @param templateFile
    //     * @param sourceFile
    //     * @param sourceUIType
    //     * @param dataflowFile
    //     * @param sinkFile
    //     * @param isUnverifiable
    //     * @param isVulnerability
    //     * @param attackSuccessString
    //     * @param headers
    //     * @param cookies
    //     * @param getParams
    //     * @param formParams
    //     */
    //    public AbstractTestCaseRequest(
    //            String fullURL,
    //            TestCaseType tcType,
    //            Category category,
    //            String name,
    //            String uiTemplateFile,
    //            String templateFile,
    //            String sourceFile,
    //            String sourceUIType,
    //            String dataflowFile,
    //            String sinkFile,
    //            boolean isUnverifiable,
    //            boolean isVulnerability,
    //            String attackSuccessString,
    //            List<RequestVariable> headers,
    //            List<RequestVariable> cookies,
    //            List<RequestVariable> getParams,
    //            List<RequestVariable> formParams) {
    //        super();
    //        this.fullURL = fullURL;
    //        this.tcType = tcType;
    //        this.category = category;
    //        this.name = name;
    //        this.uiTemplateFile = uiTemplateFile;
    //        this.templateFile = templateFile;
    //        this.sourceFile = sourceFile;
    //        this.sourceUIType = sourceUIType;
    //        this.dataflowFile = dataflowFile;
    //        this.sinkFile = sinkFile;
    //        this.isUnverifiable = isUnverifiable;
    //        this.isVulnerability = isVulnerability;
    //        this.attackSuccessString = attackSuccessString;
    //        this.headers = headers;
    //        this.cookies = cookies;
    //        this.getParams = getParams;
    //        this.formParams = formParams;
    //
    //        //        // Figure out if ANY of the values in the request include an attack value.
    //        //        this.isSafe = true;
    //        //        // Bitwise AND is done on all parameters isSafe() values. If ANY of them are
    //        // unsafe, isSafe
    //        //        // set to False.
    //        //        for (RequestVariable header : getHeaders()) {
    //        //            this.isSafe &= header.isSafe();
    //        //        }
    //        //
    //        //        for (RequestVariable cookie : getCookies()) {
    //        //            this.isSafe &= cookie.isSafe();
    //        //        }
    //        //
    //        //        for (RequestVariable getParam : getGetParams()) {
    //        //            this.isSafe &= getParam.isSafe();
    //        //        }
    //        //
    //        //        for (RequestVariable formParam : getFormParams()) {
    //        //            this.isSafe &= formParam.isSafe();
    //        //        }
    //    }

    /** Defines what parameters in the body will be sent. */
    abstract void buildBodyParameters(HttpRequestBase request);

    /** Defines what cookies will be sent. */
    abstract void buildCookies(HttpRequestBase request);

    /** Defines what headers will be sent. */
    abstract void buildHeaders(HttpRequestBase request);

    /** Defines how to construct URL query string. */
    abstract void buildQueryString();

    /**
     * TODO: Make this class a POJO TestCase and pass it as an arg to another class TestCaseRequest
     * that can build an actual HttpUriRequest.
     *
     * @return
     */
    public HttpUriRequest buildRequest() {
        buildQueryString();
        HttpRequestBase request = createRequestInstance(fullURL + query);
        buildHeaders(request);
        buildCookies(request);
        buildBodyParameters(request);
        return request;
    }

    public HttpUriRequest buildAttackRequest() {
        setSafe(false);
        return buildRequest();
    }

    public HttpUriRequest buildSafeRequest() {
        setSafe(true);
        return buildRequest();
    }

    /**
     * Method to create a POST, GET, DELETE, HEAD, OPTIONS, TRACE request object.
     *
     * @return an instance of a subclass of HttpRequestBase
     */
    abstract HttpRequestBase createRequestInstance(String URL);

    @XmlAttribute(name = "tcAttackSuccess")
    public String getAttackSuccessString() {
        return this.attackSuccessString;
    }

    @XmlAttribute(name = "tcCategory", required = true)
    @XmlJavaTypeAdapter(CategoryAdapter.class)
    @NotNull
    public Category getCategory() {
        return this.category;
    }

    @XmlElement(name = "cookie")
    @NotNull
    public List<RequestVariable> getCookies() {
        return this.cookies;
    }

    @XmlAttribute(name = "tcDataflowFile", required = true)
    @NotNull
    public String getDataflowFile() {
        return this.dataflowFile;
    }

    @XmlElement(name = "formparam")
    @NotNull
    public List<RequestVariable> getFormParams() {
        return this.formParams;
    }

    @XmlAttribute(name = "URL", required = true)
    @NotNull
    public String getFullURL() {
        return this.fullURL;
    }

    @XmlElement(name = "getparam")
    @NotNull
    public List<RequestVariable> getGetParams() {
        return this.getParams;
    }

    @XmlElement(name = "header")
    @NotNull
    public List<RequestVariable> getHeaders() {
        return this.headers;
    }

    @XmlAttribute(name = "tcName", required = true)
    @NotNull
    public String getName() {
        return this.name;
    }

    @XmlTransient
    public String getQuery() {
        return this.query;
    }

    @XmlAttribute(name = "tcSinkFile", required = true)
    @NotNull
    public String getSinkFile() {
        return this.sinkFile;
    }

    @XmlAttribute(name = "tcSourceFile", required = true)
    @NotNull
    public String getSourceFile() {
        return this.sourceFile;
    }

    @XmlAttribute(name = "tcSourceUIType", required = true)
    @NotNull
    public String getSourceUIType() {
        return this.sourceUIType;
    }

    @XmlAttribute(name = "tcTemplateFile", required = true)
    @NotNull
    public String getTemplateFile() {
        return this.templateFile;
    }

    //    @XmlAttribute(name = "tcType", required = true)
    //    @XmlReadOnly
    //    @NotNull
    public TestCaseType getType() {
        return this.tcType;
    }

    @XmlAttribute(name = "tcUITemplateFile", required = true)
    @NotNull
    public String getUiTemplateFile() {
        return this.uiTemplateFile;
    }

    public boolean isUnverifiable() {
        return getNotAutoverifiableReason() != null;
    }

    @XmlAttribute(name = "tcNotAutoverifiable")
    public String getNotAutoverifiableReason() {
        return this.notAutoverifiableReason;
    }

    @XmlAttribute(name = "tcVulnerable", required = true)
    public boolean isVulnerability() {
        return this.isVulnerability;
    }

    public boolean isSafe() {

        boolean isSafe = true;
        // Bitwise AND is done on all parameters isSafe() values. If ANY of them are unsafe, isSafe
        // set to False.
        for (RequestVariable header : getHeaders()) {
            isSafe &= header.isSafe();
        }

        for (RequestVariable cookie : getCookies()) {
            isSafe &= cookie.isSafe();
        }

        for (RequestVariable getParam : getGetParams()) {
            isSafe &= getParam.isSafe();
        }

        for (RequestVariable formParam : getFormParams()) {
            isSafe &= formParam.isSafe();
        }

        return isSafe;
    }

    public String setAttackSuccessString(String attackSuccessString) {
        return this.attackSuccessString = attackSuccessString;
    }

    public void setCategory(Category category) {
        this.category = category;
    }

    public void setCookies(List<RequestVariable> cookies) {
        this.cookies = cookies;
    }

    public void setDataflowFile(String dataflowFile) {
        this.dataflowFile = dataflowFile;
    }

    public void setFormParams(List<RequestVariable> formParams) {
        this.formParams = formParams;
    }

    public void setFullURL(String fullURL) {
        this.fullURL = fullURL;
    }

    public void setGetParams(List<RequestVariable> getParams) {
        this.getParams = getParams;
    }

    public void setHeaders(List<RequestVariable> headers) {
        this.headers = headers;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setQuery(String query) {
        this.query = query;
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

    public void setType(TestCaseType type) {
        this.tcType = type;
    }

    public void setUiTemplateFile(String uiTemplateFile) {
        this.uiTemplateFile = uiTemplateFile;
    }

    public void setNotAutoverifiableReason(String notAutoverifiableReason) {
        this.notAutoverifiableReason = notAutoverifiableReason;
    }

    public void setVulnerability(boolean isVulnerability) {
        this.isVulnerability = isVulnerability;
    }

    public void setSafe(boolean isSafe) {
        //        this.isSafe = isSafe;
        for (RequestVariable header : getHeaders()) {
            // setSafe() considers whether attack and safe values exist for this parameter before
            // setting isSafe true or false. So you don't have to check that here.
            header.setSafe(isSafe);
        }
        for (RequestVariable cookie : getCookies()) {
            cookie.setSafe(isSafe);
        }
        for (RequestVariable getParam : getGetParams()) {
            getParam.setSafe(isSafe);
        }
        for (RequestVariable formParam : getFormParams()) {
            formParam.setSafe(isSafe);
        }
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName()
                + " [category="
                + category
                + ", name="
                + name
                + ", uiTemplateFile="
                + new File(uiTemplateFile).getName()
                + ", templateFile="
                + new File(templateFile).getName()
                + ", sourceFile="
                + sourceFile
                + ", sourceUIType="
                + sourceUIType
                + ", dataflowFile="
                + dataflowFile
                + ", sinkFile="
                + sinkFile
                + ", fullURL="
                + fullURL
                + ", getParams="
                + getParams
                + ", headers="
                + headers
                + ", cookies="
                + cookies
                + ", formParams="
                + formParams
                + ", isUnverifiable="
                + isUnverifiable
                + ", isVulnerability="
                + isVulnerability
                + ", attackSuccessString="
                + attackSuccessString
                + ", isSafe="
                + isSafe()
                + ", query="
                + query
                + ", tcType="
                + tcType
                + "]";
    }
}
