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
 * <p>This reader reads JSON reports from the Horusec open source tool at:
 * https://github.com/ZupIT/horusec
 *
 * @author Sascha Knoop
 * @created 2021
 */
package org.owasp.benchmarkutils.score;

public class CweNumber {

    /** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') */
    public static int PATH_TRAVERSAL = 22;

    /**
     * CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command
     * Injection')
     */
    public static int COMMAND_INJECTION = 78;

    /**
     * CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
     */
    public static int XSS = 79;

    /**
     * CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
     */
    public static int SQL_INJECTION = 89;

    /**
     * CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
     */
    public static int LDAP_INJECTION = 90;

    /**
     * CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response
     * Splitting')
     */
    public static int HTTP_RESPONSE_SPLITTING = 113;

    /** CWE-134: Use of Externally-Controlled Format String */
    public static int EXTERNALLY_CONTROLLED_STRING = 134;

    /** CWE-327: Use of a Broken or Risky Cryptographic Algorithm */
    public static int BROKEN_CRYPTO = 327;

    /** CWE-328: Reversible One-Way Hash */
    public static int REVERSIBLE_HASH = 328;

    /** CWE-329: Generation of Predictable IV with CBC Mode */
    public static int STATIC_CRYPTO_INIT = 329;

    /** CWE-330: Use of Insufficiently Random Values */
    public static int WEAK_RANDOM = 330;

    /** CWE-352: Cross-Site Request Forgery (CSRF) */
    public static int CSRF = 352;

    /** CWE-501: Trust Boundary Violation */
    public static int TRUST_BOUNDARY_VIOLATION = 501;

    /** CWE-502: Deserialization of Untrusted Data */
    public static int INSECURE_DESERIALIZATION = 502;

    /** CWE-523: Unprotected Transport of Credentials */
    public static int UNPROTECTED_CREDENTIALS_TRANSPORT = 523;

    /** CWE-532: Insertion of Sensitive Information into Log File */
    public static int SENSITIVE_LOGFILE = 532;

    /** CWE-611: Improper Restriction of XML External Entity Reference */
    public static int XML_ENTITIES = 611;

    /** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute */
    public static int INSECURE_COOKIE = 614;

    /** CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection') */
    public static int XPATH_INJECTION = 643;

    /**
     * CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity
     * Checking
     */
    public static int OBFUSCATION = 649;

    /** CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag */
    public static int COOKIE_WITHOUT_HTTPONLY = 1004;
}
