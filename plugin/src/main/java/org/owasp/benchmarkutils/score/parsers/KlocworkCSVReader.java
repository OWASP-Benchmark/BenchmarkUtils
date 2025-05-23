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
 * @created 2025
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
        Iterable<CSVRecord> records = CSVBuilder.get().parse(inReader);

        for (CSVRecord record : records) {
            String category = record.get("Code"); // e.g., RLK.SQLOBJ
            String filename = record.get("File"); // e.g., BenchmarkTest00001

            TestCaseResult tcr = new TestCaseResult();
            if (isTestCaseFile(filename)) {
                tcr.setActualResultTestID(TestSuiteResults.getFileNameNoPath(filename));
                tcr.setCWE(cweLookup(category));
                tcr.setEvidence(category);

                int cwe = tcr.getCWE();
                if (cwe != CweNumber.DONTCARE && cwe != CweNumber.UNMAPPED) {
                    tr.put(tcr);
                }
            }
        }

        return tr;
    }

    static int cweLookup(String checkerKey) {

        switch (checkerKey) {
            case "CWARN.CONSTCOND.DO": // Condition of do statement is constant
            case "CWARN.CONSTCOND.SWITCH": // Condition of switch statement is constant
            case "CWARN.DTOR.NONVIRT.DELETE": // Obj w/ no virt methods & no virt destruct. deleted
            case "CWARN.INCL.NO_INTERFACE": // File does not include interface header
            case "ESCMP.EMPTYSTR": // Inefficient empty string comparison
            case "JD.CAST.DOWNCAST": // Possible ClassCastException for subtypes
            case "JD.METHOD.CBS": // Method can be declared static
            case "LOCRET.GLOB": // Address of local variable returned thru global var
            case "PORTING.BYTEORDER.SIZE": // Incompatible type used with network macro
            case "PORTING.CAST.FLTPNT": // Cast of floating pt expr to non-floating pt type
            case "PORTING.CAST.PTR.SIZE": // Cast to a type of possibly incompatible size
            case "PORTING.CAST.SIZE": // Expression cast to type of potentially different size
            case "PORTING.MACRO.NUMTYPE": // Macro describing a built-in numeric type is used
            case "PORTING.SIGNED.CHAR": // Char used w/out explicit signedness
            case "PRECISION.LOSS": // Conversion from A to B may cause data loss
            case "PRECISION.LOSS.CALL":
            case "REDUN.FINAL": // Redundant Final Modifier
            case "STRONG.TYPE.ASSIGN": // Strongly typed var assigned to a different strong type
            case "STRONG.TYPE.ASSIGN.ARG": // Same as prev
            case "STRONG.TYPE.ASSIGN.CONST": // Const assigned to a var of different strong type
            case "STRONG.TYPE.ASSIGN.INIT": // Value assigned to a var of different strong type
            case "STRONG.TYPE.ASSIGN.ZERO": // Zero assigned to strongly typed variable
            case "STRONG.TYPE.JOIN.CMP": // String typed value compared to value of different type
            case "STRONG.TYPE.JOIN.CONST": // Strong typed value joined w/ constant
            case "STRONG.TYPE.JOIN.EQ": // Strong typed value compared to value of different type
            case "STRONG.TYPE.JOIN.OTHER": // Strong typed value joined to value of different type
            case "STRONG.TYPE.JOIN.ZERO":
            case "SV.BFC.USING_STRUCT": // Prevent server hijacking, don't set addr to INADDR_ANY
            case "SV.EXPOSE.IFIELD": // Non-final public field could be changed by malicious
                // code/accident
            case "SV.IL.FILE": // File Name Leaking
            case "SV.IL.SESSION": // Logging of Session ID
            case "SV.IL.SESSION.CLIENT": // Shouldn't use HttpServletRequest.getRequestedSessionId()
            case "SV.LOADLIB.INJ": // Untrusted call to loadLibrary method
            case "SV.SERIAL.NON": // Class implements Serializable
            case "SV.SHARED.VAR": // Unsynchronized access to static variable from servlet
            case "SV.UMD.MAIN": // Unnecessary Main() method
            case "SV.USAGERULES.PROCESS_VARIANTS": // DRW TODO: Should this be mapped to CWE 272
                // (least priv) or others?
            case "UNUSED.FUNC.WARN": // Consider making FUNC static or add header-file decl

                // DRW TODO: These are UNMAPPED ITEMS. Figure out if they should be mapped
            case "CERT.ARR.PTR.ARITH":
            case "CXX.BITOP.BOOL_OPERAND":
            case "CXX.BITOP.NON_CONST_OPERAND":
            case "CXX.ERRNO.NOT_CHECKED":
            case "CXX.ERRNO.NOT_SET":
            case "CERT.EXPR.PARENS":
            case "CXX.CAST.OBJ_PTR_TO_OBJ_PTR":
            case "CXX.ID_VIS.GLOBAL_VARIABLE.STATIC":
            case "CXX.LOGICAL_OP.INT_OPERAND":
            case "CXX.POSSIBLE_COPY_PASTE.LOGICAL_OP.CMP_SAME_OBJECT":
            case "CXX.SUSPICIOUS_INDEX_CHECK":
            case "CXX.SUSPICIOUS_INDEX_CHECK.ZERO":
            case "NUM.OVERFLOW.DF":
            case "SV.STR_PAR.UNDESIRED_STRING_PARAMETER":
            case "SV.TAINTED.GLOBAL":
            case "SV.TAINTED.INJECTION":
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
            case "SV.TAINTED.PATH_TRAVERSAL": // Unvalidated str from extern funct used in file path
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
            case "ABV.GENERAL": // Array data may use index values greater than array size
            case "ABV.MEMBER": // Array data may use index values greater than array size
            case "ABV.STACK": // Array data may use index values greater than array size
            case "STRONG.TYPE.EXTRACT": // Strongly typed value assigned to var of different type
            case "SV.STRBO.BOUND_COPY.OVERFLOW": // Funct may incorrectly check buffer boundaries
            case "SV.STRBO.UNBOUND_COPY": // Func does not check buffer boundaries
            case "SV.TAINTED.CALL.INDEX_ACCESS": // Unvalidated value used to access array
            case "SV.TAINTED.INDEX_ACCESS": // Unvalidated value used to access array
                return 119; // Improper Restriction of Operations within Bounds of Memory Buffer
            case "SV.TAINTED.CALL.DEREF": // Unvalidated pointer is dereferenced via a call to FOO
            case "SV.TAINTED.DEREF": // Unvalidated pointer is dereferenced at line FOO
                return 123; // Write-what-where Condition
            case "SV.DOS.ARRINDEX":
                return 129; // Improper Validation of Array Index
            case "SV.FMTSTR.GENERIC":
            case "SV.TAINTED.FMTSTR":
                return 134; // Use of Externally-Controlled Format String
            case "PORTING.STORAGE.STRUCT": // Byte position of struct elements could change
                return 188; // Reliance on Data/Memory Layout
            case "SV.INT_OVF":
                return 190; // Integer Overflow
                // case "SV.IL.DEV": // App reveals design info in param back to web interface
                // return 209; // Generation of Error Message Containing Sensitive Info
            case "PORTING.UNSIGNEDCHAR.OVERFLOW.FALSE": // Express may always be false depending on
                // char signedness
            case "PORTING.UNSIGNEDCHAR.OVERFLOW.TRUE": // Express may always be true depending on
                // char signedness
                return 191; // Integer underflow
            case "SV.STRBUF.CLEAN": // Sensitive buffer not cleaned before garbage collection
                return 226; // Sensitive Info in Resource Not Removed Before Reuse
            case "SV.BANNED.REQUIRED.GETS": // Function gets is deprecated
            case "SV.UNBOUND_STRING_INPUT.FUNC": // Do not use gets, does not check buffer
                // boundaries
                return 242; // Use of Inherently Dangerous Function
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
            case "SV.TOCTOU.FILE_ACCESS":
                return 367; // TOCTOU Race Condition
            case "DBZ.GENERAL": // Data might be used in division by zero
                return 369; // Divide by zero
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
            case "CWARN.NOEFFECT.SELF_ASSIGN": // Var assigned to itself
            case "REDUN.DEF": // Assignment of variable to itself
            case "REDUN.OP": // Suspicious operation w/ same expression on both sides
                return 398; // Code quality
            case "SV.TAINTED.CALL.LOOP_BOUND": // Unvalidated value is used in loop condition thru
                // call
            case "SV.TAINTED.LOOP_BOUND": // Unvalidated value is used in loop condition
                return 400; // Uncontrolled Resource Consumption
            case "CL.MLK": // Memory leak in class
            case "MLK.MIGHT": // Memory leak
            case "MLK.MUST": // Memory leak
                return 401; // Missing Release of Memory after Effective Lifetime
            case "RH.LEAK": // Resource acquired may be lost here
                return 404; // Improper Resource Shutdown or Release
            case "CL.FFM.ASSIGN": // Operator = not defined, causing double freeing of memory
            case "CL.FFM.COPY": // Copy constructor not defined, causing double freeing of memory
            case "UFM.FFM.MIGHT": // Data freed after being freed
            case "UFM.FFM.MUST": // Data freed after being freed
                return 415; // Double Free
            case "UFM.DEREF.MIGHT": // Object dereferenced after being freed
            case "UFM.DEREF.MUST": // Object dereferenced after being freed
            case "UFM.RETURN.MIGHT": // Object returned after being freed
            case "UFM.RETURN.MUST": // Object returned after being freed
            case "UFM.USE.MIGHT": // Object used after being freed
            case "UFM.USE.MUST": // Object used after being freed
                return 416; // Use after free
            case "UNINIT.HEAP.MIGHT": // Data gets its value from uninitialized heap
            case "UNINIT.HEAP.MUST": // Data gets its value from uninitialized heap
            case "UNINIT.STACK.ARRAY.MIGHT": // Data might be used uninitialized in this function
            case "UNINIT.STACK.MIGHT": // Data might be used uninitialized in this function
            case "UNINIT.STACK.MUST": // Data is used uninitialized in this function
                return 457; // Use of uninit variable
            case "SV.DOS.TMPFILEDEL":
            case "SV.DOS.TMPFILEEXIT":
                return 459; // Incomplete Cleanup
            case "INCORRECT.ALLOC_SIZE": // Memory allocated is less than intended
                return 467; // Use of sizeof() on a Pointer Type
            case "CWARN.ALIGNMENT": // Incorrect pointer scaling is used
                return 468; // Incorrect Pointer Scaling
            case "SV.TAINT": // Unvalidated user input passed to security sensitive method
                return 470; // Unsafe Reflection
            case "NPD.CONST.DEREF":
            case "NPD.FUNC.MIGHT":
            case "NPD.GEN.CALL.MIGHT":
            case "NPD.GEN.CALL.MUST":
            case "NPD.GEN.MIGHT":
            case "NPD.GEN.MUST": // Null pointer will be dereferenced
            case "NPE.COND":
            case "NPE.CONST":
            case "NPE.RET.UTIL": // Null Pointer Returned from Map or Collection
            case "NPE.STAT":
            case "REDUN.NULL": // Use of Variable instead of Null Constant
            case "RNPD.DEREF": // Suspicious deref of pointer before null check
                return 476; // Null Pointer Dereference
            case "SV.BANNED.RECOMMENDED.SCANF": // scanf is deprecated
            case "SV.BANNED.RECOMMENDED.SPRINTF": // sprintf is deprecated
            case "SV.BANNED.RECOMMENDED.STRLEN":
            case "SV.BANNED.REQUIRED.CONCAT": // Function strncat deprecated
            case "SV.BANNED.REQUIRED.COPY": // Use of deprecated function.
            case "SV.BANNED.REQUIRED.SPRINTF": // sprintf is deprecated
                return 477; // Use of Obsolete Function
            case "CWARN.NULLCHECK.FUNCNAME": //
                return 480; // Use of Incorrect Operator
            case "ASSIGCOND.GEN": // Assignment in condition
            case "JD.BITR":
                return 481; // Assigning Instead of Comparing
            case "EFFECT": // Statement has no effect
                return 482; // Comparing instead of assigning
            case "JD.IFBAD": // Redundant 'if' statement
            case "SEMICOL": // Suspiciously placed semicolon
                return 483; // Incorrect Block Delimitation
            case "SV.EXPOSE.FIELD": // Non-final public static field could be changed
                return 500; // Public Static Field Not Marked Final
            case "SV.CODE_INJECTION.SHELL_EXEC": // Arbitrary commands can be exec thru environ vars
            case "SV.FIU.PROCESS_VARIANTS": // Its easy to run arbitrary commands thru environ vars
                return 506; // Malicious Code
            case "SV.PASSWD.HC.EMPTY": // Empty Password
                return 521; // Weak Password
            case "JD.RC.EXPR.DEAD":
            case "JD.UN.MET": // Method is never called
            case "JD.UN.PMET": // Unused Private Method
            case "UNREACH.GEN": // Code in unreachable
                return 561; // Dead Code
            case "JD.VNU":
            case "JD.VNU.NULL":
            case "LV_UNUSED.GEN":
            case "VA_UNUSED.GEN":
            case "VA_UNUSED.INIT":
                return 563; // Assignment to Variable without Use
            case "FIN.EMPTY":
            case "FIN.NOSUPER":
                return 568; // finalize() without super.finalize()
            case "CWARN.CONSTCOND.IF": // Condition in IF is constant
            case "CWARN.NOEFFECT.UCMP.LT": // Comparison is always false
            case "INVARIANT_CONDITION.UNREACH": // Condition express always yields same result,
                // causing unreachable code
                return 570; // Expression always false
                // case "CWARN.NOEFFECT.UCMP.GE": // Comparison is always true
            case "INVARIANT_CONDITION.GEN": // Condition express always yields same result
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
            case "PORTING.CAST.PTR": // Cast betw types that are not both pointers and not pointers
                return 587; // Assign Fixed Address to a Pointer
            case "FNH.MIGHT": // Freeing non-heap memory. Memory might be illegally freed
            case "FNH.MUST": // Freeing non-heap memory. Memory is illegally freed
                return 590; // Free of Memory not on the Heap
            case "CMP.STR":
                return 597; // Use of Wrong Operator in String Comparison
            case "JD.SYNC.DCL":
                return 609; // Double-Checked Locking
            case "JD.LOCK": // Lock acquired but not released
                return 667; // Improper Locking
            case "ITER.CONTAINER.MODIFIED": // Iterator i used when it can be invalidated earlier
                return 672; // Operation on Resource after Expiration or Release
            case "JD.INF.AREC":
                return 674; // Uncontrolled Recursion
            case "SV.INCORRECT_RESOURCE_HANDLING.URH": // Handler was released but still used
            case "SV.INCORRECT_RESOURCE_HANDLING.WRONG_STATUS": // Handler status wrong here
                return 675; // Multiple Ops on Rsrc in Single-Operation Context
            case "SV.UNBOUND_STRING_INPUT.CIN": // Avoid using cin, as its prone to buffer overruns
                return 676; // Use of Potentially Dangerous Function
            case "SV.TAINTED.ALLOC_SIZE": // Unvalidated int can be be used to alter memory alloc
                return 680; // Integer Overflow to Buffer Overflow
            case "SV.TAINTED.BINOP": // Unvalided int used as operand to binary operator
            case "SV.TAINTED.CALL.BINOP": // Unvalided int used as operand to binary operator
                return 682; // Incorrect Calculation
            case "SV.FMT_STR.PRINT_PARAMS_WRONGNUM.FEW": // Too few params provided for sprintf call
                return 685; // Funct Call w/ Incorrect Number of Args
            case "SV.FMT_STR.PRINT_FORMAT_MISMATCH.BAD": // sprintf fmt spec expects type char* but
                // has incompatible type
                return 688; // Call w/ Incorrect Var or Ref as Argument
            case "NPD.CHECK.MUST": // Pointer checked for null will be dereferenced
                // case "NPD.FUNC.MIGHT": // Pointer ret from call may be null and be dereferenced
            case "NPD.FUNC.CALL.MUST": // Pointer ret from call may be null and passed to func
            case "NPD.FUNC.MUST": // Pointer ret from call may be null and be dereferenced
            case "NPE.RET": // Null Pointer Returned from Method
                return 690; // Unchecked Return Value to Null Pointer Dereference
            case "JD.BITCMP": // Questionable use of Bit compare operation
                return 754; // Improper Check for Unusual or Exceptional Conditions
            case "SV.HASH.NO_SALT": // Use of a one-way cryptographic hash without a salt
                return 759; // CWE-759: Use of a One-Way Hash without a Salt
                // Not the same as: CweNumber.WEAK_HASH_ALGO; - CWE: 328 Weak Hashing
            case "CL.FMM": // Possible freeing of mismatched memory
            case "FREE.INCONSISTENT": // Memory freed here but not at function exit
                return 762; // Mismatched Memory Management Routines
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
            case "INFINITE_LOOP.LOCAL":
                return 835; // Infinite Loop
            case "SV.DATA.DB": // Data Injection - Untrusted data inserted into a Database
                return 1287; // Improper Validation of Specified Type of Input

            default:
                System.out.println(
                        "WARNING: Unmapped Klocwork Vuln category detected: " + checkerKey);
                return CweNumber.UNMAPPED;
        }
    }
}
