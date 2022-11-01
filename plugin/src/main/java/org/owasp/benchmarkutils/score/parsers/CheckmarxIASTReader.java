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
 * @author Yuuki Endo / Jason Khoo
 * @created 2020
 */
package org.owasp.benchmarkutils.score.parsers;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.BenchmarkScore;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class CheckmarxIASTReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).contains("CWE")
                && resultFile.line(0).contains("URL")
                && !resultFile.line(0).contains("SeekerServerLink");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr = new TestSuiteResults("CxIAST", true, TestSuiteResults.ToolType.IAST);

        java.io.Reader inReader = new java.io.StringReader(resultFile.content());
        Iterable<CSVRecord> records = CSVFormat.RFC4180.withFirstRecordAsHeader().parse(inReader);
        for (CSVRecord record : records) {
            String checkerKey = record.get("Vulnerability Type");
            String url = record.get("URL");
            //      System.out.println("URL = "+url); //For debugging YE

            TestCaseResult tcr = new TestCaseResult();
            tcr.setCategory(checkerKey);
            tcr.setCWE(cweLookup(checkerKey));
            Pattern testCasePattern =
                    Pattern.compile(
                            BenchmarkScore.TESTCASENAME
                                    + "[0-9]{"
                                    + BenchmarkScore.TESTIDLENGTH
                                    + "}");
            Matcher testCaseMatcher = testCasePattern.matcher(url);
            if (testCaseMatcher.find()) {
                String testCase = testCaseMatcher.group(0);
                // System.out.println("testCase = "+testCase+" Test Num =
                // "+testCase.substring(testCase.length()-Utils.TESTCASE_DIGITS,
                // testCase.length())); // For debugging YE
                tcr.setTestCaseName(testCase);
                // BenchmarkTest00000 - BenchmarkTest99999
                tcr.setNumber(
                        Integer.parseInt(
                                testCase.substring(
                                        testCase.length() - BenchmarkScore.TESTIDLENGTH)));
                if (!CweNumber.DONTCARE.equals(tcr.getCWE())) {
                    tr.put(tcr);
                }
            }
        }
        tr.setTime("100");
        return tr;
    }

    private CweNumber cweLookup(String checkerKey) {
        //    checkerKey = checkerKey.replace("-SECOND-ORDER", "");

        switch (checkerKey) {
            case "App_DOS_Database_Connections":
                return CweNumber.UNCONTROLLED_RESOURCE_CONSUMPTION; // App_DOS_Database_Connections
            case "Blind_SQL_Injection":
                return CweNumber.SQL_INJECTION;
            case "Click_Jacking":
                return CweNumber.PROTECTION_MECHANISM_FAILURE;
            case "Command_Injection":
                return CweNumber.OS_COMMAND_INJECTION;
            case "CORS":
                return CweNumber.ORIGIN_VALIDATION_ERROR;
            case "CSRF":
                return CweNumber.CSRF;
            case "Debug_Mode_Enabled":
                return CweNumber.SENSITIVE_INFO_IN_DEBUG_MODE;
            case "Deserialize_Vulnerability":
                return CweNumber.INSECURE_DESERIALIZATION;
            case "Failed_Login_Without_Audit":
                return CweNumber.INSUFFICIENT_LOGGING;
            case "File_Upload_To_Unprotected_Directory":
                return CweNumber.UNRESTRICTED_FILE_UPLOAD;
            case "Improper_HTTP_Get_Usage":
                return CweNumber.TRUSTING_SERVER_HTTP;
            case "Insecure_Cookie":
            case "Session_Id_Disclosure": // CxIAST does not define but it is same as
                // Insecure_Cookie YE
                return CweNumber.INSECURE_COOKIE;
            case "Insecure_Outgoing_Communication":
                return CweNumber.UNENCRYPTED_SENSITIVE_DATA;
            case "Insufficient_Session_Expiration":
                return CweNumber.INSUFFICIENT_SESSION_EXPIRATION;
            case "LDAP_Injection":
                return CweNumber.LDAP_INJECTION;
            case "Least_Privilege_Violation":
                return CweNumber.TOO_PRIVILIGED_EXECUTION;
            case "Log_Forging":
                return CweNumber.MISSING_LOG_OUTPUT_NEUTRALIZATION;
            case "Missing_X_Content_Type_Options_Header":
                return CweNumber.PROTECTION_MECHANISM_FAILURE;
            case "Missing_X_XSS_Protection_Header":
                return CweNumber.PROTECTION_MECHANISM_FAILURE;
            case "NoSQL_Injection":
                return CweNumber.IMPROPER_DATA_QUERY_NEUTRALIZATION;
            case "Open_Redirect":
                return CweNumber.OPEN_REDIRECT;
            case "Parameter_Pollution":
                return CweNumber.IMPROPER_HANDLING_OF_PARAMETERS;
            case "Parameter_Tampering":
                return CweNumber.RESOURCE_INJECTION;
            case "Path_Traversal":
                return CweNumber.PATH_TRAVERSAL;
            case "Second_Order_Command_Injection":
                return CweNumber.COMMAND_INJECTION;
            case "Second_Order_LDAP_Injection":
                return CweNumber.LDAP_INJECTION;
            case "Second_Order_Path_Traversal":
                return CweNumber.PATH_TRAVERSAL;
            case "Second_Order_SQL_Injection":
                return CweNumber.SQL_INJECTION;
            case "Second_Order_XPath_Injection":
                return CweNumber.XPATH_INJECTION;
            case "Sensitive_Data_Exposure_Credit_Card":
            case "Sensitive_Data_Exposure_Email":
            case "Sensitive_Data_Exposure_Long_Number":
                return CweNumber.UNENCRYPTED_SENSITIVE_DATA;
            case "SQL_Injection":
                return CweNumber.SQL_INJECTION;
            case "Stored_XSS":
                return CweNumber.XSS;
            case "Successful_Login_Without_Audit":
                return CweNumber.INSUFFICIENT_LOGGING;
            case "Trust_Boundary_Violation":
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case "Weak_Cryptography":
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "Weak_DB_Password":
                return CweNumber.WEAK_PASSWORD_REQUIREMENTS;
            case "Weak_Hashing":
                return CweNumber.WEAK_HASH_ALGO;
            case "Weak_Random":
                return CweNumber.WEAK_RANDOM;
            case "XPath_Injection":
                return CweNumber.XPATH_INJECTION;
            case "XSS":
                return CweNumber.XSS;
            case "XXE":
                return CweNumber.XXE;

            default:
                System.out.println(
                        "WARNING: Unmapped Vulnerability category detected: " + checkerKey);
        }
        return CweNumber.DONTCARE;
    }
}
