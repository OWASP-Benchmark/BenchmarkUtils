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
 * @author Dave Wichers
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.StringReader;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVRecord;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

/**
 * The Klocwork CSV reader parses the CSV generated when you go to a Klocwork project in the web
 * portal and export a projects Issues using the CSV export button.
 */
public class KlocworkCSVReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".csv")
                && resultFile.line(0).contains("State")
                && resultFile.line(0).contains("Taxonomy");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("Klocwork", true, TestSuiteResults.ToolType.SAST);

        /* The start of a Klocwork .csv results file looks like this:

        ID,Status,Severity,Severity Code,Support Level,Support Level Code,State,Code,Title,Message,File,Method,Owner,Taxonomy,Date Originated,Line,URL,Issue Ids,Comment,Trace,Reference,Bug Tracker Id,Bug Tracker URL,Justification

        1,Analyze,Review,4,Klocwork Supported,2,New,EXC.BROADTHROWS,Method has an overly broad throws declaration,The 'methodNAME' method throws a generic exception 'java.lang.Throwable',/PATHTO/src/main/java/testcases/DIR/TESTFILENAME.java,methodNAME,unowned,Java,1728492492310,,"http://klocwork:8080/review/insight-review.html#issuedetails_goto:problemid=1,project=PROJECTNAME,searchquery=",[],,,,,,

        */
        java.io.BufferedReader inReader =
                new java.io.BufferedReader(new StringReader(resultFile.content()));

        String header = inReader.readLine();
        CSVFormat.Builder CSVBuilder = CSVFormat.Builder.create(CSVFormat.RFC4180);
        CSVBuilder.setHeader(header.split(","));
        Iterable<CSVRecord> records = CSVBuilder.build().parse(inReader);

        for (CSVRecord record : records) {
            String category = record.get("Code"); // e.g., RLK.SQLOBJ
            String filename = record.get("File"); // e.g., BenchmarkTest00001

            TestCaseResult tcr = new TestCaseResult();
            if (isTestCaseFile(filename)) {
                tcr.setActualResultTestID(TestSuiteResults.getFileNameNoPath(filename));
                tcr.setCWE(cweLookup(category));
                tcr.setEvidence(category);

                int cwe = tcr.getCWE();
                if (cwe != CweNumber.DONTCARE && cwe != CweNumber.UNKNOWN) {
                    tr.put(tcr);
                }
            }
        }

        return tr;
    }

    static int cweLookup(String checkerKey) {

        switch (checkerKey) {
            case "ESCMP.EMPTYSTR": // Inefficient empty string comparison
            case "JD.CAST.DOWNCAST": // Possible ClassCastException for subtypes
            case "JD.METHOD.CBS": // Method can be declared static
            case "REDUN.FINAL": // Redundant Final Modifier
            case "SV.IL.FILE": // File Name Leaking
            case "SV.IL.SESSION": // Logging of Session ID
            case "SV.IL.SESSION.CLIENT": // HttpServletRequest.getRequestedSessionId() should not be
                // used
            case "SV.EXPOSE.IFIELD": // Non-final public field could be changed by malicious code or
                // accident
            case "SV.LOADLIB.INJ": // Untrusted call to loadLibrary method
            case "SV.SERIAL.NON": // Class implements Serializable
            case "SV.SHARED.VAR": // Unsynchronized access to static variable from servlet
            case "SV.UMD.MAIN": // Unnecessary Main() method
                return CweNumber.DONTCARE;

            case "SV.DATA.BOUND": // Untrusted Data leaks into trusted storage
                return CweNumber.TRUST_BOUNDARY_VIOLATION;
            case "SV.EXEC": // Process Injection
            case "SV.EXEC.ENV": // Process Injection Environment Variables
            case "SV.EXEC.LOCAL": // Process Injection. Local Arguments
            case "SV.EXEC.PATH": // Untrusted Search Path
                return CweNumber.COMMAND_INJECTION;
            case "SV.LDAP": // Unvalidated user input is used as LDAP filter
                return CweNumber.LDAP_INJECTION;
            case "SV.PATH": // Path and file name injection
            case "SV.PATH.INJ": // File injection
                return CweNumber.PATH_TRAVERSAL;
            case "SV.RANDOM": // Use of insecure Random number generator
                return CweNumber.WEAK_RANDOM;
            case "SV.SSRF.URI":
                return CweNumber.SSRF;
            case "SV.SQL": // SQL Injection
            case "SV.SQL.DBSOURCE": // Unchecked info from DB used in SQL Statement
                return CweNumber.SQL_INJECTION;
            case "SV.WEAK.CRYPT": // Use of a Broken or Risky Cryptographic Algorithm
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "SV.XPATH": // Unvalidated user input is used as an XPath expression
                return CweNumber.XPATH_INJECTION;
            case "SV.XSS.COOKIE": // Sensitive cookie without setHttpOnly flag
                return CweNumber.COOKIE_WITHOUT_HTTPONLY;
            case "SV.XSS.COOKIE.SECURE":
                return CweNumber.INSECURE_COOKIE;
            case "SV.XSS.DB": // Cross Site Scripting (Stored XSS)
            case "SV.XSS.REF": // Cross Site Scripting (Reflected XSS)
                return CweNumber.XSS;
            case "SV.XXE.DBF": // Possibility for XML External Entity attack
            case "SV.XXE.SF":
            case "SV.XXE.SPF":
            case "SV.XXE.TF":
            case "SV.XXE.XIF":
            case "SV.XXE.XRF":
                return CweNumber.XXE;

            case "SV.TAINT_NATIVE":
                return 111; // Direct Use of Unsafe JNI
            case "SV.HTTP_SPLIT":
                return 113; // HTTP Response Splitting
            case "SV.LOG_FORGING":
                return 117; // Log Forging
            case "SV.DOS.ARRINDEX":
                return 129; // Improper Validation of Array Index
            case "SV.INT_OVF":
                return 190; // Integer Overflow
                // case "SV.IL.DEV": // App reveals design info in param back to web interface
                // return 209; // Generation of Error Message Containing Sensitive Info
            case "SV.STRBUF.CLEAN": // Sensitive buffer not cleaned before garage collection
                return 226; // Sensitive Info in Resource Not Removed Before Reuse
            case "SV.SOCKETS":
                return 246; // J2EE: Direct Use of Sockets
            case "JD.UNCAUGHT":
                return 248; // Uncaught Exception
            case "RR.IGNORED":
                return 252; // Unchecked Return Value
            case "SV.PASSWD.PLAIN": // Plain-text Password
                return 256; // Plaintext Storage of a Password
            case "SV.PASSWD.HC":
            case "SV.PASSWD.HC.MINLEN": // Minimum 15 char length Hardcoded pwd
            case "SV.PASSWD.PLAIN.HC":
                return 259; // Hardcoded Password
            case "SV.SENSITIVE.DATA": // Unencrypted sensitive data is written
                return 312; // Cleartext Storage of Sensitive Info
            case "SV.UMC.EXIT":
            case "UMC.EXIT":
                return 382; // J2EE: Use of System.exit()
            case "SV.UMC.THREADS":
                return 383; // J2EE: Direct Use of Threads
            case "ECC.EMPTY": // Empty Exception Block
            case "JD.IFEMPTY":
                return 390; // Detection of Error Condition w/out Action
            case "JD.CATCH":
                return 395; // Catch NullPointerException
            case "EXC.BROADTHROWS":
                return 397; // Decl of Throws for Generic Exception
            case "REDUN.DEF": // Assignment of variable to itself
            case "REDUN.OP": // Suspicious operation w/ same expression on both sides
                return 398; // Code quality
            case "SV.DOS.TMPFILEDEL":
            case "SV.DOS.TMPFILEEXIT":
                return 459; // Incomplete Cleanup
            case "SV.TAINT": // Unvalidated user input passed to security sensitive method
                return 470; // Unsafe Reflection
            case "NPE.COND":
            case "NPE.CONST":
            case "NPE.RET.UTIL": // Null Pointer Returned from Map or Collection
            case "NPE.STAT":
            case "REDUN.NULL": // Use of Variable instead of Null Constant
                return 476; // Null Pointer Dereference
            case "JD.BITR":
                return 481; // Assigning Instead of Comparing
            case "JD.IFBAD": // Redundant 'if' statement
                return 483; // Incorrect Block Delimitation
            case "SV.EXPOSE.FIELD": // Non-final public static field could be changed
                return 500; // Public Static Field Not Marked Final
            case "SV.PASSWD.HC.EMPTY": // Empty Password
                return 521; // Weak Password
            case "JD.RC.EXPR.DEAD":
            case "JD.UN.MET": // Method is never called
            case "JD.UN.PMET": // Unused Private Method
                return 561; // Dead Code
            case "JD.VNU":
            case "JD.VNU.NULL":
                return 563; // Assignment to Variable without Use
            case "FIN.EMPTY":
            case "FIN.NOSUPER":
                return 568; // finalize() without super.finalize()
            case "JD.RC.EXPR.CHECK":
                return 571; // Expression always true
            case "JD.THREAD.RUN":
                return 572; // Call to Thread run() instead of start()
            case "SV.SERIAL.NOREAD": // Method readObject() should be defined for serializable class
            case "SV.SERIAL.NOWRITE": // Method writeObject() should be defined for serializable
                // class
                return 573; // Improper Following of Spec by Caller
            case "EHC.EQ":
            case "EHC.HASH":
                return 581; // Just One of Equals and Hashcode Defined
            case "SV.EXPOSE.MUTABLEFIELD": // Public field references mutable object
                return 582; // Array Declared Public, Final, Static
            case "JD.FINRET":
                return 584; // Return in Finally Block
            case "JD.UMC.FINALIZE":
                return 586; // Explicit Call to Finalize()
            case "CMP.STR":
                return 597; // Use of Wrong Operator in String Comparison
            case "JD.SYNC.DCL":
                return 609; // Double-Checked Locking
            case "JD.LOCK": // Lock acquired but not released
                return 667; // Improper Locking
            case "JD.INF.AREC":
                return 674; // Uncontrolled Recursion
            case "NPE.RET": // Null Pointer Returned from Method
                return 690; // Unchecked Return Value to Null Pointer Dereference
            case "JD.BITCMP": // Questionable use of Bit compare operation
                return 754; // Improper Check for Unusual or Exceptional Conditions
            case "SV.HASH.NO_SALT": // Use of a one-way cryptographic hash without a salt
                return 759; // CWE-759: Use of a One-Way Hash without a Salt
                // Not the same as: CweNumber.WEAK_HASH_ALGO; - CWE: 328 Weak Hashing
            case "RLK.SQLCON": // SQL Connection not closed on exit
            case "RLK.SQLOBJ": // SQL Object not closed on exit
                return 772; // Missing Release of Resource after Effective Lifetime
            case "RLK.IN": // Input stream not closed on exit
            case "RLK.OUT": // Output stream not closed on exit
            case "RLK.ZIP":
                return 775; // Missing Release of File Descriptor
            case "JD.INF.ALLOC": // Memory alloc in infinite loop can lead to OutOfMemoryError
            case "SV.DOS.ARRSIZE": // Unvalidated user input used for array size
                return 789; // Memory alloc w/ Excessive Size Value
            case "JD.SYNC.IN":
            case "JD.LOCK.SLEEP":
                return 833; // Deadlock
            case "SV.DATA.DB": // Data Injection - Untrusted data inserted into a Database
                return 1287; // Improper Validation of Specified Type of Input

            default:
                System.out.println(
                        "WARNING: Unmapped Klocwork Vuln category detected: " + checkerKey);
                return CweNumber.UNKNOWN;
        }
    }
}
