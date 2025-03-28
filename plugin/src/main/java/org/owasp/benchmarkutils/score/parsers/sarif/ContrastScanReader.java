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
 * @author Sascha Knoop
 * @created 2022
 */
package org.owasp.benchmarkutils.score.parsers.sarif;

import java.util.HashMap;
import java.util.Map;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ContrastScanReader extends SarifReader {

    public ContrastScanReader() {
        super("Contrast Scan", true, CweSourceType.CUSTOM);
    }

    @Override
    public Map<String, Integer> customRuleCweMappings(JSONObject driver) {
        Map<String, Integer> ruleCweMap = new HashMap<>();

        // The following are the ruleIds for Contrast scan for Java war/jar files
        ruleCweMap.put("unsafe-code-execution", CweNumber.COMMAND_INJECTION);
        ruleCweMap.put("cmd-injection", CweNumber.COMMAND_INJECTION);
        ruleCweMap.put("cookie-flags-missing", CweNumber.INSECURE_COOKIE);
        ruleCweMap.put("crypto-bad-ciphers", CweNumber.WEAK_CRYPTO_ALGO);
        ruleCweMap.put("crypto-bad-mac", CweNumber.WEAK_HASH_ALGO);
        ruleCweMap.put("crypto-weak-randomness", CweNumber.WEAK_RANDOM);
        ruleCweMap.put("header-injection", CweNumber.HTTP_RESPONSE_SPLITTING);
        ruleCweMap.put("hql-injection", CweNumber.HIBERNATE_INJECTION);
        ruleCweMap.put("ldap-injection", CweNumber.LDAP_INJECTION);
        ruleCweMap.put("log-injection", 117);
        ruleCweMap.put("nosql-injection", CweNumber.SQL_INJECTION);
        ruleCweMap.put("path-traversal", CweNumber.PATH_TRAVERSAL);
        ruleCweMap.put("reflected-xss", CweNumber.XSS);
        ruleCweMap.put("reflection-injection", 470); // CWE-470 Unsafe Reflection
        ruleCweMap.put("sql-injection", CweNumber.SQL_INJECTION);
        ruleCweMap.put("trust-boundary-violation", CweNumber.TRUST_BOUNDARY_VIOLATION);
        // CWE-111 Direct Use of Unsafe JNI
        ruleCweMap.put("unmanaged-code-invocation", 111);
        // CWE-770 Allocation of Resources Without Limits or Throttling
        ruleCweMap.put("unsafe-readline", 770);
        // CWE-601 URL Redirection to Untrusted Site (Open Redirect)
        ruleCweMap.put("unvalidated-redirect", 601);
        ruleCweMap.put("xpath-injection", CweNumber.XPATH_INJECTION);
        ruleCweMap.put("xxe", CweNumber.XXE);
        ruleCweMap.put("autocomplete-missing", 522); // CWE-522 Insufficiently Protected Creds

        // The following are the ruleIds for Contrast scan for HTML source code files
        // See HTML rules: https://docs.contrastsecurity.com/en/html-scan-rules.html
        ruleCweMap.put(
                "OPT.HTML.MissingPasswordFieldMasking",
                549); // CWE-549 Missing Password Field Masking

        // The following are the ruleIds for Contrast scan for Java source code files
        // See Java rules: https://docs.contrastsecurity.com/en/java-scan-rules.html

        // Don't access/modify java.security config objects (Policy, Security, Provider, Principal,
        // KeyStore)
        ruleCweMap.put("OPT.JAVA.EJB.DontModifyAccessSecurity", CweNumber.DONTCARE);
        ruleCweMap.put("OPT.JAVA.RGS.CMP", 486); // Comparison of Classes by Name
        // Java access restriction subverted by using reflection. (e.g., protected/private methods).
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.AccessibilitySubversionRule", 506); // Malicious Code
        // CWE-111 Direct Use of Unsafe JNI
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.AvoidNativeCallsRule", 111);
        // CWE-245: Direct Mgt of Connection
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.AvoidJ2EEDirectDatabaseConnection", 245);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.AvoidJ2EEExplicitSocket", 246); // Direct Use of Sockets
        ruleCweMap.put(
                "OPT.JAVA.SEC_JAVA.AvoidJ2EEExplicitThreadManagement",
                383); // Direct Use of Threads
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.AvoidJ2EEJvmExit", 382); // Use of System.exit()
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.AvoidJ2EELeftoverDebugCode", 489); // Active Debug Code
        // CWE-502: Deserialization of Untrusted Data
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.CodeInjectionWithDeserializationRule", 502);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.CodeInjectionRule", 94); // Code Injection
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.CommandInjectionRule", CweNumber.COMMAND_INJECTION);
        // XHSM. No CWE
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.CrossSiteRequestForgeryRule", CweNumber.CSRF);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.CrossSiteHistoryManipulation", CweNumber.DONTCARE);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.CrossSiteScriptingRule", CweNumber.XSS);
        // CWE-676: Use of Potentially Dangerous Function
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.ESAPIBannedRule", 676);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.ExecutionAfterRedirect", 698); // Execution after Redirect
        // CWE-134: Use of Externally-Controlled Format String
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.ExternalControlOfConfigurationSetting", 134);
        // CWE-15: External Control of System or Configuration Setting
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.FormatStringInjectionRule", 15);
        // CWE-321: Hard-coded Crypto Key
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.HardcodedCryptoKey", 321);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.HardcodedUsernamePassword", 798); // Hardcoded Creds
        // CWE-235: Improper Handling Extra Params
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.HttpParameterPollutionRule", 235);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.HttpSplittingRule", 113); // HTTP Req/Resp Splitting
        // Mapping InadequatePaddingRule to CWE-327 Weak Crypto, causes LOTS of False Positives
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.InadequatePaddingRule", CweNumber.DONTCARE);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.InformationExposureThroughErrorMessage", 209);
        // CWE-20: Improper Input Validation
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.InputPathNotCanonicalizedRule", 20);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.InsecureRandomnessRule", CweNumber.WEAK_RANDOM);
        // CWE-319: Cleartext transmission of sensitive data
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.InsecureTransport", 319);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.LdapInjectionRule", CweNumber.LDAP_INJECTION);
        // CWE-329: Generation of Predictable IV with CBC Mode
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.NonRandomIVWithCBCMode", 329);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.OpenRedirectRule", 601); // CWE-601 Open Redirect
        ruleCweMap.put(
                "OPT.JAVA.SEC_JAVA.PasswordInCommentRule", 615); // Sensitive Info in Comments
        ruleCweMap.put(
                "OPT.JAVA.SEC_JAVA.PasswordInConfigurationFile", 256); // Plaintext Password Storage
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.PathTraversalRule", CweNumber.PATH_TRAVERSAL);
        // CWE-315: Cleartext Storage of Sensitive Info in Cookie
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.PlaintextStorageInACookieRule", 315);
        ruleCweMap.put(
                "OPT.JAVA.SEC_JAVA.PlaintextStorageOfPassword", 256); // Plaintext Password Storage
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.PotentialInfiniteLoop", 835); // Infinite Loop
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.ProcessControlRule", 114); // Process Control
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.ServerSideRequestForgeryRule", 918); // SSRF
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.SqlInjectionRule", CweNumber.SQL_INJECTION);
        ruleCweMap.put(
                "OPT.JAVA.SEC_JAVA.TrustBoundaryViolationRule", CweNumber.TRUST_BOUNDARY_VIOLATION);
        ruleCweMap.put(
                "OPT.JAVA.SEC_JAVA.UnnormalizedInputString", 20); // Improper Input Validation
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.UnsafeCookieRule", 614); // No secure attribute
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.UnsafeReflection", 470); // Unsafe Reflection
        // CWE-566: Authorization Bypass Thru User-Controlled SQL Primary Key
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.UserControlledSQLPrimaryKey", 566);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.WeakCryptographicHashRule", CweNumber.WEAK_HASH_ALGO);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.WeakEncryptionRule", CweNumber.WEAK_CRYPTO_ALGO);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.WebXmlSecurityMisconfigurationsRule", CweNumber.DONTCARE);
        ruleCweMap.put("OPT.JAVA.SEC_JAVA.XPathInjectionRule", CweNumber.XPATH_INJECTION);

        // The following are the ruleIds for Contrast scan for CSharp source code files
        // See CSharp rules: https://docs.contrastsecurity.com/en/c--scan-rules.html

        ruleCweMap.put(
                "OPT.CSHARP.AvoidNullReferenceException", 395); // Use of NPE Catch to Detect NPE
        ruleCweMap.put("OPT.CSHARP.AvoidSystemOutputStream", CweNumber.DONTCARE);
        // CWE-582: Array Declared Public, Final, and Static
        ruleCweMap.put("OPT.CSHARP.Csharp.ArrayFieldsShouldNotBeReadOnly", 582);
        // CWE-94: Improper Control of Generation of Code ('Code Injection')
        ruleCweMap.put("OPT.CSHARP.CodeInjection", 94);
        // CWE-502: Deserialization of Untrusted Data
        ruleCweMap.put("OPT.CSHARP.CodeInjectionWithDeserialization", 502);
        ruleCweMap.put("OPT.CSHARP.CrossSiteScripting", CweNumber.XSS);
        ruleCweMap.put("OPT.CSHARP.InsecureRandomness", CweNumber.WEAK_RANDOM);
        ruleCweMap.put("OPT.CSHARP.LdapInjection", CweNumber.LDAP_INJECTION);
        ruleCweMap.put("OPT.CSHARP.NullDereference", 476); // Null Pointer Dereference
        ruleCweMap.put("OPT.CSHARP.OpenRedirect", 601); // CWE-601 Open Redirect
        ruleCweMap.put("OPT.CSHARP.PathTraversal", CweNumber.PATH_TRAVERSAL);
        // CWE-315: Cleartext Storage of Sensitive Info in Cookie
        ruleCweMap.put("OPT.CSHARP.PlaintextStorageInACookie", 315);
        ruleCweMap.put("OPT.CSHARP.PotentialInfiniteLoop", 835); // Infinite Loop
        ruleCweMap.put("OPT.CSHARP.ResourceLeakDatabase", 400); // Uncontrolled Resource Consumption
        ruleCweMap.put("OPT.CSHARP.ResourceLeakStream", 400); // Uncontrolled Resource Consumption
        ruleCweMap.put(
                "OPT.CSHARP.ResourceLeakUnmanaged", 400); // Uncontrolled Resource Consumption
        // CWE-235: Improper Handling Extra Params
        ruleCweMap.put("OPT.CSHARP.SEC.ConnectionStringParameterPollution", 235);
        ruleCweMap.put("OPT.CSHARP.SEC.HardcodedCredential", 798); // Hardcoded Credentials
        // CWE-1051: Initialization w/ Hard-Coded Network Resource Data (Prohibited Vuln Mapping)
        ruleCweMap.put("OPT.CSHARP.SEC.HardcodedNetworkAddress", 1051);
        ruleCweMap.put("OPT.CSHARP.SEC.HttpSplittingRule", 113); // HTTP Req/Resp Splitting
        ruleCweMap.put("OPT.CSHARP.SEC.InformationExposureThroughErrorMessage", 209);
        // CWE-319: Cleartext transmission of sensitive data
        ruleCweMap.put("OPT.CSHARP.SEC.InsecureTransport", 319);
        ruleCweMap.put(
                "OPT.CSHARP.SEC.PlaintextStorageOfPassword", 256); // Plaintext Password Storage
        // CWE-15: External Control of System or Configuration Setting
        ruleCweMap.put("OPT.CSHARP.SEC.RegistryManipulation", 15);
        // CWE-427: Uncontrolled Search Path - "attacker can change search path to resources"
        ruleCweMap.put("OPT.CSHARP.SEC.SettingManipulation", 427);
        ruleCweMap.put("OPT.CSHARP.SEC.TemporaryFilesLeft", 459); // Incomplete Cleanup
        ruleCweMap.put("OPT.CSHARP.SEC.UnsafeCookieRule", 614); // No secure attribute
        ruleCweMap.put("OPT.CSHARP.SqlInjection", CweNumber.SQL_INJECTION);
        // CWE497: Exposure of Sensitive Info to Unauthorized Control Sphere
        ruleCweMap.put("OPT.CSHARP.SystemInformationLeak", 497);
        ruleCweMap.put(
                "OPT.CSHARP.UncheckedInputInLoopCondition",
                606); // Unchecked Input for Loop Condition
        ruleCweMap.put("OPT.CSHARP.UncheckedReturnValue", 252); // Unchecked Return Value
        ruleCweMap.put("OPT.CSHARP.WeakCryptographicHash", CweNumber.WEAK_HASH_ALGO);
        ruleCweMap.put("OPT.CSHARP.WeakKeySize", CweNumber.WEAK_CRYPTO_ALGO);
        ruleCweMap.put("OPT.CSHARP.WeakSymmetricEncryptionAlgorithm", CweNumber.WEAK_CRYPTO_ALGO);
        ruleCweMap.put("OPT.CSHARP.XPathInjection", CweNumber.XPATH_INJECTION);

        // The following are the ruleIds for Contrast scan for C source code files
        // See the C rules: https://docs.contrastsecurity.com/en/c-scan-rules.html
        // The bulk of these are mapped from:
        //   - https://wiki.sei.cmu.edu/confluence/display/c/2+Rules
        //   - https://wiki.sei.cmu.edu/confluence/display/c/3+Recommendations
        // The 2008 version of the CERT C Secure Coding standard has these mappings for various
        // INTxx rules:
        //   - https://cwe.mitre.org/data/definitions/738.html

        // Do not use out-of-bounds pointers/array subscripts on arrays
        ruleCweMap.put("OPT.C.CERTC.ARR30", 119); // CWE-119 Improper Restrict of Ops in Mem Buff
        // Guarantee copies are made into storage of sufficient size
        ruleCweMap.put("OPT.C.CERTC.ARR33", 170); // CWE-170 Improper Null Termination
        // DRW Test 129 below
        ruleCweMap.put("OPT.C.CERTC.ARR35", 129); // Do not allow loops to iterate beyond array end

        // Do not call system() if you don't need a command processor
        ruleCweMap.put(
                "OPT.C.CERTC.ENV04", 2223); // DRW TODO: Related to CWE-78 OS Command Injection?
        ruleCweMap.put("OPT.C.CERTC.EXP01", 467); // CWE-467 Use of sizeof() on a Pointer Type
        ruleCweMap.put("OPT.C.CERTC.EXP33", 457); // Use of Uninitialized Variable
        ruleCweMap.put("OPT.C.CERTC.EXP34", 476); // Null Pointer Dereference

        // Be careful using functions that use file names for identification
        // SEI also suggests this maps to CWE-73 External control of file or path & CWE-367 TOCTOU
        // Race Condition
        ruleCweMap.put("OPT.C.CERTC.FIO01", 676); // CWE-676 Use of Potentially Dangerous Function
        // Exclude unsanitized user input from format strings
        ruleCweMap.put("OPT.C.CERTC.FIO30", 134); // CWE-134 Uncontrolled Format String
        // Detect/Handle I/O errors resulting in undefined behavior
        // DRW TODO: Test if this is right mapping
        ruleCweMap.put("OPT.C.CERTC.FIO33", 475); // CWE-475 Undefined Behavior for Input to API
        // DRW TODO: Test when real test suite available to test
        ruleCweMap.put(
                "OPT.C.CERTC.FIO36", 3334); // Do not assume new-line char read when using fgets()
        // Do not assume fgets()/fgetws() returns a nonempty string when successful
        // DRW TODO: Test if this is right mapping. CWE 241 is not mapped to any existing test case
        // categories
        ruleCweMap.put(
                "OPT.C.CERTC.FIO37", 241); // CWE-241 Improper Handling of Unexpected Data type
        // Creation of Temp File in Dir w/ Incorrect Permissions
        ruleCweMap.put(
                "OPT.C.CERTC.FIO43", 379); // CWE-379 Creation of Temp File in Dir w/Insecure Perms

        // Use bitwise operators only on unsigned operands
        ruleCweMap.put("OPT.C.CERTC.INT13", 682); // CWE-682 Incorrect Calculation

        // Allocate/free memory in same module at same level of abstraction
        // SEI suggests this maps to CWE-415 Double Free & CWE-416 Use after free -DRW TODO test
        ruleCweMap.put("OPT.C.CERTC.MEM00", 666); // CWE-666 Operation on Resource Wrong Phase
        // Do not access freed memory
        ruleCweMap.put("OPT.C.CERTC.MEM30", 416); // CWE-416 Use After Free
        // Free dynamically allocated memory when no longer needed
        ruleCweMap.put("OPT.C.CERTC.MEM31", 401); // CWE-401 Memory Leak

        // Detect and handle memory allocation errors - DRW TODO test
        // SEI for the CPP MEM52 rule of the same name, suggests this maps to CWEs: 252, 391, 476,
        // 690, 703, 754. But these are all related to error handling. Ultimately I think this
        // results in a buffer overflow, so mapping to that. Test this made up mapping to see if it
        // makes sense.
        ruleCweMap.put("OPT.C.CERTC.MEM32", 7777); // CWE- TBD

        // Only free memory allocated dynamically
        ruleCweMap.put("OPT.C.CERTC.MEM34", 590); // CWE-590 Free of Memory Not on Heap
        // DRW TODO: Test the test cases this maps to, to make sure its the right mapping
        // Allocate sufficient memory for an object
        ruleCweMap.put("OPT.C.CERTC.MEM35", 131); // CWE-131 Incorrect Calculation of Buffer Size
        // DRW TODO - Prob don't care - Might be related to Path Traversal - Test w/real test suite
        // SEI does not map this recommendation to any CWE
        ruleCweMap.put("OPT.C.CERTC.PRE02", 3356);
        // CweNumber.DONTCARE); // Macro replacement lists should be parenthesized

        // Call only asynchronous-safe functions within signal handlers
        ruleCweMap.put(
                "OPT.C.CERTC.SIG30", 479); // CWE-479 Signal Handler Use of Non-reentrant Function

        // Sanitize data passed to sensitive subsystems
        // SEI suggests this maps to CWE-78 Failure to sanitize data to OS command & CWE-488
        // Argument injection or modification
        // DRW TODO: Test when real test suite available to test
        ruleCweMap.put("OPT.C.CERTC.STR02", 6667);
        // Make sure there is enough room for the string and its null terminator
        ruleCweMap.put("OPT.C.CERTC.STR31", 120); // CWE-120 Buffer Overflow
        // Null terminate byte strings as required
        ruleCweMap.put("OPT.C.CERTC.STR32", 170); // CWE-170 Improper Null Termination
        // Size wide char strings correctly
        ruleCweMap.put(
                "OPT.C.CERTC.STR33", 135); // CWE-135 Incorrect Calc of Multi-byte String Length
        // Do not copy data from unbounded source to fixed-length array
        ruleCweMap.put("OPT.C.CERTC.STR35", 120); // CWE-120 Buffer Overflow

        // DRW TODO: Verify that CWE-170 Improper Null Termination is the right CWE
        ruleCweMap.put(
                "OPT.C.CERTC.STR36", 170); // Don't specify bound of char array init w/literal
        ruleCweMap.put("OPT.C.CorrectUseMemoryLeaks", 401); // Missing Release of Memory
        ruleCweMap.put("OPT.C.SEC.HardcodedUsernamePassword", 798); // Hardcoded Creds
        ruleCweMap.put(
                "OPT.C.SEC.InsufficientKeySize", 326); // CWE-326 Inadequate Encryption Strength
        ruleCweMap.put("OPT.C.SEC.PathTraversal", CweNumber.PATH_TRAVERSAL);
        ruleCweMap.put("OPT.C.SEC.WeakCryptographicHash", CweNumber.WEAK_HASH_ALGO);
        ruleCweMap.put("OPT.C.SEC.WeakEncryption", CweNumber.WEAK_CRYPTO_ALGO);

        // The following are the ruleIds for Contrast scan for C++ source code files
        // See the C++ rules: https://docs.contrastsecurity.com/en/cpp-scan-rules.html
        // The bulk of these are mapped from:
        //   - https://wiki.sei.cmu.edu/confluence/display/cplusplus/2+Rules
        //   - https://wiki.sei.cmu.edu/confluence/display/cplusplus/3+Recommendations

        // Do not use out-of-bounds pointers/array subscripts on arrays
        ruleCweMap.put("OPT.CPP.CERTC.ARR30", 119); // CWE-119 Improper Restrict of Ops in Mem Buff
        // Guarantee copies are made into storage of sufficient size
        ruleCweMap.put("OPT.CPP.CERTC.ARR33", 170); // CWE-170 Improper Null Termination
        // DRW Test 129 below
        ruleCweMap.put(
                "OPT.CPP.CERTC.ARR35", 129); // Do not allow loops to iterate beyond array end
        // Do not call system() if you don't need a command processor
        ruleCweMap.put(
                "OPT.CPP.CERTC.ENV04", 2222); // DRW TODO: Related to CWE-78 OS Command Injection?

        ruleCweMap.put("OPT.CPP.CERTC.EXP01", 467); // CWE-467 Use of sizeof() on a Pointer Type
        ruleCweMap.put("OPT.CPP.CERTC.EXP33", 457); // Use of Uninitialized Variable
        ruleCweMap.put("OPT.CPP.CERTC.EXP34", 476); // Null Pointer Dereference

        // Exclude unsanitized user input from format strings
        ruleCweMap.put("OPT.CPP.CERTC.FIO30", 134); // CWE-134 Uncontrolled Format String
        // Detect/Handle I/O errors resulting in undefined behavior
        // DRW TODO: Test if this is right mapping
        ruleCweMap.put("OPT.CPP.CERTC.FIO33", 475); // CWE-475 Undefined Behavior for Input to API
        // DRW TODO: Test when real test suite available to test
        ruleCweMap.put(
                "OPT.CPP.CERTC.FIO36", 3333); // Do not assume new-line char read when using fgets()

        // Use bitwise operators only on unsigned operands
        ruleCweMap.put("OPT.CPP.CERTC.INT13", 682); // CWE-682 Incorrect Calculation

        // Allocate/free memory in same module at same level of abstraction
        // SEI suggests this maps to CWE-415 Double Free & CWE-416 Use after free -DRW TODO test
        ruleCweMap.put("OPT.CPP.CERTC.MEM00", 666); // CWE-666 Operation on Resource Wrong Phase

        // Do not access freed memory
        ruleCweMap.put("OPT.CPP.CERTC.MEM30", 416); // CWE-416 Use After Free

        // Detect and handle memory allocation errors - DRW TODO test
        // SEI for the CPP MEM52 rule of the same name, suggests this maps to CWEs: 252, 391, 476,
        // 690, 703, 754. But these are all related to error handling. Ultimately I think this
        // results in a buffer overflow, so mapping to that. Test this made up mapping to see if it
        // makes sense.
        ruleCweMap.put("OPT.CPP.CERTC.MEM32", 7778); // CWE- TBD

        // DRW TODO: Test the test cases this maps to, to make sure its the right mapping
        // Allocate sufficient memory for an object
        ruleCweMap.put("OPT.CPP.CERTC.MEM35", 131); // CWE-131 Incorrect Calculation of Buffer Size
        // DRW TODO - Prob don't care - Might be related to Path Traversal - Test w/real test suite
        // SEI does not map this recommendation to any CWE
        ruleCweMap.put("OPT.CPP.CERTC.PRE02", 3355);
        // CweNumber.DONTCARE); // Macro replacement lists should be parenthesized

        // Sanitize data passed to sensitive subsystems
        // SEI suggests this maps to CWE-78 Failure to sanitize data to OS command & CWE-488
        // Argument injection or modification
        // DRW TODO: Test when real test suite available to test
        ruleCweMap.put(
                "OPT.CPP.CERTC.STR02",
                6666); // Avoid using signals to implement normal functionality

        // Make sure there is enough room for the string and its null terminator
        ruleCweMap.put("OPT.CPP.CERTC.STR31", 120); // CWE-120 Buffer Overflow
        // Null terminate byte strings as required
        ruleCweMap.put("OPT.CPP.CERTC.STR32", 170); // CWE-170 Improper Null Termination
        // Size wide char strings correctly
        ruleCweMap.put(
                "OPT.CPP.CERTC.STR33", 135); // CWE-135 Incorrect Calc of Multi-byte String Length
        // DRW TODO: Verify that CWE-170 Improper Null Termination is the right CWE
        // This also causes CWE-125 Out of Bounds Read, so maybe that's the right CWE?
        ruleCweMap.put(
                "OPT.CPP.CERTC.STR36", 170); // Don't specify bound of char array init w/literal
        ruleCweMap.put("OPT.CPP.CorrectUseMemoryLeaks", 401); // Missing Release of Memory
        ruleCweMap.put("OPT.CPP.DontUseCast", 704); // Incorrect Type Conversion or Cast
        ruleCweMap.put("OPT.CPP.SEC.HardcodedUsernamePassword", 798); // Hardcoded Creds
        ruleCweMap.put("OPT.CPP.SEC.PathTraversal", CweNumber.PATH_TRAVERSAL);
        ruleCweMap.put("OPT.CPP.SEC.ProcessControl", 114); // CWE-114 Process Control

        return ruleCweMap;
    }

    @Override
    public void setVersion(ResultFile resultFile, TestSuiteResults testSuiteResults) {
        // SARIF file contains several nulls as version, just ignoring it
        // Instead, we use the 'version' to set the type of CodeSec scan. WAR, JAR, SAST, etc.
        JSONObject firstrun = resultFile.json().getJSONArray("runs").getJSONObject(0);
        String commandLine =
                firstrun.getJSONArray("invocations").getJSONObject(0).getString("commandLine");

        if (commandLine.contains("contrast-scan-java-cli")) {
            if (commandLine.endsWith("jar")) testSuiteResults.setToolVersion("OfJAR");
            else if (commandLine.endsWith("war")) testSuiteResults.setToolVersion("OfWAR");
        } else if (commandLine.contains("sast-engine"))
            testSuiteResults.setToolVersion("OfSourceCode");
    }
}
