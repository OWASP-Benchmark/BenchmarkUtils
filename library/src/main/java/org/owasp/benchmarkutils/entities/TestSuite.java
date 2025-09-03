/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https:/owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author David Anderson
 * @created 2021
 */
package org.owasp.benchmarkutils.entities;

import java.util.List;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;

@XmlRootElement(name = "TestSuite")
public class TestSuite {
    private List<TestCase> testCases;

    private String name;

    private String version;

    CloseableHttpClient httpclient = null;

    @XmlElement(name = "TestCase")
    public List<TestCase> getTestCases() {
        return testCases;
    }

    public void setTestCases(List<TestCase> testCases) {
        this.testCases = testCases;
    }

    @XmlAttribute(required = true)
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @XmlAttribute(required = true)
    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    //    public void execute() {
    //
    //        // TODO: Maybe create a TestCaseContext class to hold the httpclient, and setup tasks
    // like
    //        // starting the DB server and app server.  Pass this object as the argument to
    // execute().
    //        // It is annoying that the httpclient field of the class will be null if there are no
    // Http
    //        // test cases in the test suite.  It would be better if we had a context class for
    // each
    //        // TestCaseInput class.
    //        // The XML doc that defines the testcases could specify the config class by class
    // name.  The
    //        // testcase class would need to instantiate the named class accessible via a singleton
    // map.
    //        // Then, each testcase can call a shared setup method and access shared state via its
    // own
    //        // config field.  I think this means that the DB server would be started in the middle
    // of
    //        // parsing the XML doc, though.
    //
    //        TestCaseContext context = TestCase.getContext(testCase);
    //        testCase.execute(context);
    //
    //        // Execute all of the test cases
    //        for (TestCase testCase : this.getTestCases()) {
    //            testCase.execute();
    //        }
    //    }

    @Override
    public String toString() {
        return "TestSuite [testCases=" + testCases + "]";
    }
}
