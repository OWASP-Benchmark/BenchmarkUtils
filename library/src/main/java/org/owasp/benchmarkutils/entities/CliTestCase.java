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

import javax.xml.bind.annotation.XmlElement;

public class CliTestCase extends TestCase {

    private ExecutableTestCaseInput testCaseInput;

    @Override
    @XmlElement(name = "input", required = true)
    public ExecutableTestCaseInput getTestCaseInput() {
        return testCaseInput;
    }

    //    public void execute() {
    //
    //		// FIXME: What would the executable testcase's attackRequest look like?
    //	    HttpUriRequest attackRequest = getTestCaseInput().buildAttackRequest();
    //	    HttpUriRequest safeRequest = getTestCaseInput().buildSafeRequest();
    //
    //	    // Send the next test case request with its attack payload
    //	    ResponseInfo attackPayloadResponseInfo = sendRequest(httpclient, attackRequest);
    //	    responseInfoList.add(attackPayloadResponseInfo);
    //
    //	    // Log the response
    //	    log(attackPayloadResponseInfo);
    //
    //	    ResponseInfo safePayloadResponseInfo = null;
    //	    if (!isUnverifiable()) {
    //	        // Send the next test case request with its safe payload
    //	        safePayloadResponseInfo = sendRequest(httpclient, safeRequest);
    //	        responseInfoList.add(safePayloadResponseInfo);
    //
    //	        // Log the response
    //	        log(safePayloadResponseInfo);
    //	    }
    //
    //	    TestCaseVerificationResults result =
    //	            new TestCaseVerificationResults(
    //	                    attackRequest,
    //	                    safeRequest,
    //	                    this,
    //	                    attackPayloadResponseInfo,
    //	                    safePayloadResponseInfo);
    //
    //	    // Verify the response
    //	    if (RegressionTesting.isTestingEnabled) {
    //	        handleResponse(result);
    //	    }
    //
    //	    return result;
    //    }
}
