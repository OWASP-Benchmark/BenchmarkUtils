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
