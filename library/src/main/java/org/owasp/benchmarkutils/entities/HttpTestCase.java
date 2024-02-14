package org.owasp.benchmarkutils.entities;

public class HttpTestCase extends TestCase {

    //	@Override
    //    @XmlElement(name = "input", required = true)
    //    public HttpTestCaseInput getTestCaseInput() {
    //        return testCaseInput;
    //    }

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
