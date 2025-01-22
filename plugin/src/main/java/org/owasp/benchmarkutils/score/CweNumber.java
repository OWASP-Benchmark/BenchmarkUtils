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
 * @author Sascha Knoop
 * @created 2021
 */
package org.owasp.benchmarkutils.score;

public class CweNumber {

    /** Used occasionally to indicate a CWE isn't mapped yet, but might get mapped properly later */
    public static final int UNMAPPED = -1;

    /** To be used when the CWE reported is one we don't care about in any test suite */
    public static final int DONTCARE = 0000;

    /** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') */
    public static final int PATH_TRAVERSAL = 22;

    /** CWE-23: Relative Path Traversal */
    public static final int RELATIVE_PATH_TRAVERSAL = 23;

    /**
     * CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command
     * Injection')
     */
    public static final int COMMAND_INJECTION = 78;

    /**
     * CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
     */
    public static final int XSS = 79;

    /**
     * CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
     */
    public static final int SQL_INJECTION = 89;

    /**
     * CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
     */
    public static final int LDAP_INJECTION = 90;

    /** CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') */
    public static final int CRLF_INJECTION = 93;

    /**
     * CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response
     * Splitting')
     */
    public static final int HTTP_RESPONSE_SPLITTING = 113;

    /** CWE-134: Use of Externally-Controlled Format String */
    public static final int EXTERNALLY_CONTROLLED_STRING = 134;

    /** CWE-284: Improper Access Control */
    public static final int IMPROPER_ACCESS_CONTROL = 284;

    /** CWE-327: Use of a Broken or Risky Cryptographic Algorithm */
    public static final int WEAK_CRYPTO_ALGO = 327;

    /** CWE-328: Use of Weak Hash */
    public static final int WEAK_HASH_ALGO = 328;

    /** CWE-329: Generation of Predictable IV with CBC Mode */
    public static final int STATIC_CRYPTO_INIT = 329;

    /** CWE-330: Use of Insufficiently Random Values */
    public static final int WEAK_RANDOM = 330;

    /** CWE-352: Cross-Site Request Forgery (CSRF) */
    public static final int CSRF = 352;

    /** CWE-382: J2EE Bad Practices: Use of System.exit() */
    public static final int SYSTEM_EXIT = 382;

    /** CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference */
    public static final int CATCHING_NULL_POINTER_EXCEPTION = 395;

    /** CWE-396: Declaration of Catch for Generic Exception */
    public static final int CATCH_GENERIC_EXCEPTION = 396;

    /** CWE-397: Declaration of Throws for Generic Exception */
    public static final int THROW_GENERIC_EXCEPTION = 397;

    /** CWE-478: Missing Default Case in Switch Statement */
    public static final int MISSING_DEFAULT_CASE = 478;

    /** CWE-483: Incorrect Block Delimitation */
    public static final int INCORRECT_BLOCK_DELIMITATION = 483;

    /** CWE-484: Omitted Break Statement in Switch */
    public static final int OMITTED_BREAK = 484;

    /** CWE-493: Critical Public Variable Without Final Modifier */
    public static final int PUBLIC_VAR_WITHOUT_FINAL = 493;

    /** CWE-500: Public Static Field Not Marked Final */
    public static final int PUBLIC_STATIC_NOT_FINAL = 500;

    /** CWE-501: Trust Boundary Violation */
    public static final int TRUST_BOUNDARY_VIOLATION = 501;

    /** CWE-502: Deserialization of Untrusted Data */
    public static final int INSECURE_DESERIALIZATION = 502;

    /** CWE-523: Unprotected Transport of Credentials */
    public static final int UNPROTECTED_CREDENTIALS_TRANSPORT = 523;

    /** CWE-532: Insertion of Sensitive Information into Log File */
    public static final int SENSITIVE_LOGFILE = 532;

    /** CWE-564: SQL Injection: Hibernate */
    public static final int HIBERNATE_INJECTION = 564;

    /** CWE-572: Call to Thread run() instead of start() */
    public static final int THREAD_WRONG_CALL = 572;

    /** CWE-580: clone() Method Without super.clone() */
    public static final int CLONE_WITHOUT_SUPER_CLONE = 580;

    /** CWE-563: Assignment to Variable without Use */
    public static final int UNUSED_VAR_ASSIGNMENT = 563;

    /** CWE-581: Object Model Violation: Just One of Equals and Hashcode Defined */
    public static final int OBJECT_MODEL_VIOLATION = 581;

    /** CWE-583: finalize() Method Declared Public */
    public static final int FINALIZE_DECLARED_PUBLIC = 583;

    /** CWE-584: Return Inside Finally Block */
    public static final int RETURN_INSIDE_FINALLY = 584;

    /** CWE-595: Comparison of Object References Instead of Object Contents */
    public static final int OBJECT_REFERENCE_COMPARISON = 595;

    /** CWE-601: URL Redirection to Untrusted Site ('Open Redirect') */
    public static final int OPEN_REDIRECT = 601;

    /** CWE-611: Improper Restriction of XML External Entity Reference */
    public static final int XXE = 611;

    /** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute */
    public static final int INSECURE_COOKIE = 614;

    /** CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection') */
    public static final int XPATH_INJECTION = 643;

    /**
     * CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity
     * Checking
     */
    public static final int OBFUSCATION = 649;

    /** CWE-754: Improper Check for Unusual or Exceptional Conditions */
    public static final int IMPROPER_CHECK_FOR_CONDITIONS = 754;

    /** CWE-783: Operator Precedence Logic Error */
    public static final int OPERATOR_PRECEDENCE_LOGIC = 783;

    /** CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop') */
    public static final int LOOP_WITH_UNREACHABLE_EXIT = 835;

    /** CWE-916: Use of Password Hash With Insufficient Computational Effort */
    public static final int PASSWORD_HASH_WITH_INSUFFICIENT_COMPUTATIONAL_EFFORT = 916;

    /** CWE-918: Server-Side Request Forgery (SSRF) */
    public static final int SSRF = 918;

    /** CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag */
    public static final int COOKIE_WITHOUT_HTTPONLY = 1004;

    /** CWE-1021: Improper Restriction of Rendered UI Layers or Frames */
    public static final int IMPROPER_UI_LAYER_RESTRICTION = 1021;

    /** CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine */
    public static final int SSTI = 1336;
}
