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

public enum CweNumber {

    /** To be used when the CWE reported is one we don't care about in any test suite */
    DONTCARE(0),

    /** CWE-16: CWE CATEGORY: Configuration */
    CATEGORY_CONFIGURATION(16),

    /** CWE-20: Improper Input Validation */
    IMPROPER_INPUT_VALIDAITON(20),

    /** CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') */
    PATH_TRAVERSAL(22),

    /** CWE-73: External Control of File Name or Path */
    EXTERNAL_FILE_OR_PATH_CONTROL(73),

    /**
     * CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component
     * ('Injection')
     */
    GENERAL_INJECTION(74),

    /**
     * CWE-77: Improper Neutralization of Special Elements used in a Command ('Command Injection')
     */
    COMMAND_INJECTION(77),

    /**
     * CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command
     * Injection')
     */
    OS_COMMAND_INJECTION(78),

    /**
     * CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
     */
    XSS(79),

    /** CWE-83: Improper Neutralization of Script in Attributes in a Web Page */
    IMPROPER_NEUTRALIZATION_OF_ATTRIBUTES(83),

    /**
     * CWE-88: Improper Neutralization of Argument Delimiters in a Command ('Argument Injection')
     */
    ARGUMENT_INJECTION(88),

    /**
     * CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
     */
    SQL_INJECTION(89),

    /**
     * CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')
     */
    LDAP_INJECTION(90),

    /** CWE-91: XML Injection (aka Blind XPath Injection) */
    BLIND_XPATH_INJECTION(91),

    /** CWE-93: Improper Neutralization of CRLF Sequences ('CRLF Injection') */
    CRLF_INJECTION(93),

    /**
     * CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval
     * Injection')
     */
    EVAL_INJECTION(95),

    /** CWE-99: Improper Control of Resource Identifiers ('Resource Injection') */
    RESOURCE_INJECTION(99),

    /** CWE-112: Missing XML Validation */
    MISSING_XML_VALIDATION(112),

    /**
     * CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Response
     * Splitting')
     */
    HTTP_RESPONSE_SPLITTING(113),

    /** CWE-117: Improper Output Neutralization for Logs */
    MISSING_LOG_OUTPUT_NEUTRALIZATION(117),

    /** CWE-120: Buffer Copy without Checking Size of Input ('Classic Buffer Overflow') */
    CLASSIC_BUFFER_OVERFLOW(120),

    /** CWE-134: Use of Externally-Controlled Format String */
    EXTERNALLY_CONTROLLED_STRING(134),

    /** CWE-180: Incorrect Behavior Order: Validate Before Canonicalize */
    INCORRECT_BEHAVIOUR_ORDER(180),

    /** CWE-182: Collapse of Data into Unsafe Value */
    COLLAPSE_DATA_IN_UNSAFE_VALUE(182),

    /** CWE-190: Integer Overflow or Wraparound */
    INTEGER_OVERFLOW_WRAPAROUND(190),

    /** CWE-200: Exposure of Sensitive Information to an Unauthorized Actor */
    EXPOSURE_SENSITIVE_TO_UNAUTHORIZED_USER(200),

    /** CWE-205: Observable Behavioral Discrepancy */
    OBSERVABLE_BEHAVIORAL_DISCREPANCY(205),

    /** CWE-209: Generation of Error Message Containing Sensitive Information */
    ERROR_MESSAGE_WITH_SENSITIVE_INFO(209),

    /** CWE-215: Insertion of Sensitive Information Into Debugging Code */
    SENSITIVE_INFO_IN_DEBUG_MODE(215),

    /** CWE-235: Improper Handling of Extra Parameters */
    IMPROPER_HANDLING_OF_PARAMETERS(235),

    /** CWE-244: Improper Clearing of Heap Memory Before Release ('Heap Inspection') */
    HEAP_INSPECTION(244),

    /** CWE-248: Uncaught Exception */
    UNCAUGHT_EXCEPTION(248),

    /** CWE-250: Execution with Unnecessary Privileges */
    TOO_PRIVILIGED_EXECUTION(250),

    /** CWE-252: Unchecked Return Value */
    UNCHECKED_RETURN_VALUE(252),

    /** CWE-259: Use of Hard-coded Password */
    HARDCODED_PASSWORD(259),

    /** CWE-284: Improper Access Control */
    IMPROPER_ACCESS_CONTROL(284),

    /** CWE-285: Improper Authorization */
    IMPROPER_AUTHORIZATION(285),

    /** CWE-293: Using Referer Field for Authentication */
    REFERER_FIELD_IN_AUTHENTICATION(293),

    /** CWE-295: Improper Certificate Validation */
    IMPROPER_CERTIFICATE_VALIDATION(295),

    /** CWE-311: Missing Encryption of Sensitive Data */
    UNENCRYPTED_SENSITIVE_DATA(311),

    /** CWE-315: Cleartext Storage of Sensitive Information in a Cookie */
    UNENCRYPTED_SENSITIVE_INFO_STORED_IN_COOKIE(315),

    /** CWE-319: Cleartext Transmission of Sensitive Information */
    CLEARTEXT_TRANSMISSION_OF_SENSITIVE_INFO(319),

    /** CWE-320: CWE CATEGORY: Key Management Errors */
    CATEGORY_KEY_MANAGEMENT_ERROR(320),

    /** CWE-325: Missing Cryptographic Step */
    MISSING_CRYPTOGRAPHIC_STEP(325),

    /** CWE-327: Use of a Broken or Risky Cryptographic Algorithm */
    WEAK_CRYPTO_ALGO(327),

    /** CWE-328: Use of Weak Hash */
    WEAK_HASH_ALGO(328),

    /** CWE-329: Generation of Predictable IV with CBC Mode */
    STATIC_CRYPTO_INIT(329),

    /** CWE-330: Use of Insufficiently Random Values */
    WEAK_RANDOM(330),

    /** CWE-332: Insufficient Entropy in PRNG */
    INSUFFICIENT_ENTRUPY_IN_PNRG(332),

    /** CWE-345: Insufficient Verification of Data Authenticity */
    INSUFFICIENT_DATA_AUTHENTICITY_VERIFICATION(345),

    /** CWE-346: Origin Validation Error */
    ORIGIN_VALIDATION_ERROR(346),

    /** CWE-352: Cross-Site Request Forgery (CSRF) */
    CSRF(352),

    /** CWE-353: Missing Support for Integrity Check */
    MISSING_SUPPORT_FOR_INTEGRITY_CHECK(353),

    /** CWE-359: Exposure of Private Personal Information to an Unauthorized Actor */
    EXPOSURE_PRIVATE_TO_UNAUTHORIZED_USER(359),

    /**
     * CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race
     * Condition')
     */
    RACE_CONDITION(362),

    /** CWE-369: Divide By Zero */
    DIVISION_BY_ZERO(369),

    /** CWE-374: Passing Mutable Objects to an Untrusted Method */
    PASS_MUTABLE_OBJECT_TO_UNTRUSTED_MODULE(374),

    /** CWE-379: Creation of Temporary File in Directory with Insecure Permissions */
    TEMPORARY_FILE_WITH_INSECURE_PERMISSIONS(379),

    /** CWE-382: J2EE Bad Practices: Use of System.exit() */
    SYSTEM_EXIT(382),

    /** CWE-390: Detection of Error Condition Without Action */
    DETECTING_ERROR_WITHOUT_ACTION(390),

    /** CWE-391: Unchecked Error Condition */
    UNCHECKED_ERROR_CONDITION(391),

    /** CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference */
    CATCHING_NULL_POINTER_EXCEPTION(395),

    /** CWE-396: Declaration of Catch for Generic Exception */
    CATCH_GENERIC_EXCEPTION(396),

    /** CWE-397: Declaration of Throws for Generic Exception */
    THROW_GENERIC_EXCEPTION(397),

    /** CWE-398: CWE CATEGORY: 7PK - Code Quality */
    CATEGORY_CODE_QUALITY(398),

    /** CWE-400: Uncontrolled Resource Consumption */
    UNCONTROLLED_RESOURCE_CONSUMPTION(400),

    /** CWE-404: Improper Resource Shutdown or Release */
    UNRELEASED_RESOURCE(404),

    /** CWE-434: Unrestricted Upload of File with Dangerous Type */
    UNRESTRICTED_FILE_UPLOAD(434),

    /** CWE-436: Interpretation Conflict */
    INTERPRETATION_CONFLICT(436),

    /** CWE-440: Expected Behavior Violation */
    EXPECTED_BEHAVIOUR_VIOLATION(440),

    /** CWE-451: User Interface (UI) Misrepresentation of Critical Information */
    MISREPRESENTATION_OF_CRITICAL_INFO(451),

    /** CWE-459: Incomplete Cleanup */
    INCOMPLETE_CLEANUP(459),

    /**
     * CWE-470: Use of Externally-Controlled Input to Select Classes or Code ('Unsafe Reflection')
     */
    UNSAFE_REFLECTION(470),

    /** CWE-472: External Control of Assumed-Immutable Web Parameter */
    EXTERNAL_CONTROL_OF_WEB_PARAM(472),

    /** CWE-474: Use of Function with Inconsistent Implementations */
    FUNCTION_WITH_INCONSISTENT_IMPLEMENTATION(474),

    /** CWE-476: NULL Pointer Dereference */
    NULL_POINTER_DEREFERENCE(476),

    /** CWE-477: Use of Obsolete Function */
    OBSOLETE_FUNCTION_USAGE(477),

    /** CWE-478: Missing Default Case in Switch Statement */
    MISSING_DEFAULT_CASE(478),

    /** CWE-482: Comparing instead of Assigning */
    COMPARING_INSTEAD_OF_ASSIGNING(482),

    /** CWE-483: Incorrect Block Delimitation */
    INCORRECT_BLOCK_DELIMITATION(483),

    /** CWE-484: Omitted Break Statement in Switch */
    OMITTED_BREAK(484),

    /** CWE-486: Comparison of Classes by Name */
    COMPARISON_BY_CLASS_NAME(486),

    /** CWE-489: Active Debug Code */
    ACTIVE_DEBUG_CODE(489),

    /** CWE-493: Critical Public Variable Without Final Modifier */
    PUBLIC_VAR_WITHOUT_FINAL(493),

    /** CWE-494: Download of Code Without Integrity Check */
    MISSING_INTEGRITY_CHECK_FOR_DOWNLOADED_CODE(494),

    /** CWE-497: Exposure of Sensitive System Information to an Unauthorized Control Sphere */
    EXPOSE_SYSTEM_INFO_TO_UNAUTHORIZED_CONTROL(497),

    /** CWE-499: Serializable Class Containing Sensitive Data */
    SERIALIZABLE_CLASS_WITH_SENSITIVE_DATA(499),

    /** CWE-500: Public Static Field Not Marked Final */
    PUBLIC_STATIC_NOT_FINAL(500),

    /** CWE-501: Trust Boundary Violation */
    TRUST_BOUNDARY_VIOLATION(501),

    /** CWE-502: Deserialization of Untrusted Data */
    INSECURE_DESERIALIZATION(502),

    /** CWE-521: Weak Password Requirements */
    WEAK_PASSWORD_REQUIREMENTS(521),

    /** CWE-522: Insufficiently Protected Credentials */
    INSUFFICIENTLY_RPOTECTED_CREDENTIALS(522),

    /** CWE-523: Unprotected Transport of Credentials */
    UNPROTECTED_CREDENTIALS_TRANSPORT(523),

    /** CWE-525: Use of Web Browser Cache Containing Sensitive Information */
    SENSITIVE_INFORMATION_IN_BROWSER_CACHE(525),

    /** CWE-530: Exposure of Backup File to an Unauthorized Control Sphere */
    EXPOSE_BACKUP_TO_UNAUTHORIZED_TARGET(530),

    /** CWE-532: Insertion of Sensitive Information into Log File */
    SENSITIVE_LOGFILE(532),

    /** CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory */
    SENSITIVE_INFO_IN_EXTERNAL_ACCESSIBLE_SPACE(538),

    /** CWE-539: Use of Persistent Cookies Containing Sensitive Information */
    PERSISTENT_COOKIE_CONTAINS_SENSITIVE_INFO(539),

    /** CWE-541: Inclusion of Sensitive Information in an Include File */
    SENSITIVE_INFORMATION_IN_INCLUDED_FILE(541),

    /** CWE-547: Use of Hard-coded, Security-relevant Constants */
    HARDCODED_SECURITY_RELEVANT_CONSTANTS(547),

    /** CWE-561: Dead Code */
    DEAD_CODE(561),

    /** CWE-563: Assignment to Variable without Use */
    UNUSED_VAR_ASSIGNMENT(563),

    /** CWE-564: SQL Injection: Hibernate */
    HIBERNATE_INJECTION(564),

    /** CWE-565: Reliance on Cookies without Validation and Integrity Checking */
    MISSING_COOKIE_VALIDATION(565),

    /** CWE-567: Unsynchronized Access to Shared Data in a Multithreaded Context */
    UNSYNCHRONIZED_ACCESS_TO_SHARED_DATA(567),

    /** CWE-570: Expression is Always False */
    EXPRESSION_ALWAYS_FALSE(570),

    /** CWE-571: Expression is Always True */
    EXPRESSION_ALWAYS_TRUE(571),

    /** CWE-572: Call to Thread run() instead of start() */
    THREAD_WRONG_CALL(572),

    /** CWE-579: J2EE Bad Practices: Non-serializable Object Stored in Session */
    NON_SERIALIZABLE_OBJECT_IN_SESSION(579),

    /** CWE-580: clone() Method Without super.clone() */
    CLONE_WITHOUT_SUPER_CLONE(580),

    /** CWE-581: Object Model Violation: Just One of Equals and Hashcode Defined */
    OBJECT_MODEL_VIOLATION(581),

    /** CWE-582: Array Declared Public, Final, and Static */
    STATIC_FINAL_ARRAY_IS_PUBLIC(582),

    /** CWE-583: finalize() Method Declared Public */
    FINALIZE_DECLARED_PUBLIC(583),

    /** CWE-584: Return Inside Finally Block */
    RETURN_INSIDE_FINALLY(584),

    /** CWE-594: J2EE Framework: Saving Unserializable Objects to Disk */
    SAVING_UNSERIALIZABLE_OBJECT_TO_DISK(594),

    /** CWE-595: Comparison of Object References Instead of Object Contents */
    OBJECT_REFERENCE_COMPARISON(595),

    /** CWE-600: Uncaught Exception in Servlet */
    UNCAUGHT_EXCEPTION_IN_SERVLET(600),

    /** CWE-601: URL Redirection to Untrusted Site ('Open Redirect') */
    OPEN_REDIRECT(601),

    /** CWE-606: Unchecked Input for Loop Condition */
    UNCHECKED_INPUT_FOR_LOOP_CONDITION(606),

    /** CWE-607: Public Static Final Field References Mutable Object */
    PUBLIC_STATIC_FINAL_MUTABLE_OBJECT(607),

    /** CWE-611: Improper Restriction of XML External Entity Reference */
    XXE(611),

    /** CWE-613: Insufficient Session Expiration */
    INSUFFICIENT_SESSION_EXPIRATION(613),

    /** CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute */
    INSECURE_COOKIE(614),

    /** CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection') */
    XPATH_INJECTION(643),

    /**
     * CWE-649: Reliance on Obfuscation or Encryption of Security-Relevant Inputs without Integrity
     * Checking
     */
    OBFUSCATION(649),

    /** CWE-650: Trusting HTTP Permission Methods on the Server Side */
    TRUSTING_SERVER_HTTP(650),

    /** CWE-652: Improper Neutralization of Data within XQuery Expressions ('XQuery Injection') */
    XQUERY_INJECTION(652),

    /** CWE-676: Use of Potentially Dangerous Function */
    USE_POTENTIALLY_DANGEROUS_FUNCTION(676),

    /** CWE-681: Incorrect Conversion between Numeric Types */
    INCORRECT_NUMERIC_TYPE_CONVERSION(681),

    /** CWE-693: Protection Mechanism Failure */
    PROTECTION_MECHANISM_FAILURE(693),

    /** CWE-703: Improper Check or Handling of Exceptional Conditions */
    IMPROPER_CHECK_FOR_EXCEPTION_CONDITIONS(703),

    /** CWE-732: Incorrect Permission Assignment for Critical Resource */
    INCORRECT_PERMISSIONS_FOR_CRITICAL_RESOURCE(732),

    /** CWE-754: Improper Check for Unusual or Exceptional Conditions */
    IMPROPER_CHECK_FOR_CONDITIONS(754),

    /** CWE-760: Use of a One-Way Hash with a Predictable Salt */
    ONE_WAY_HASH_WITH_PREDICTABLE_SALT(760),

    /** CWE-759: Use of a One-Way Hash without a Salt */
    UNSALTED_ONE_WAY_HASH(759),

    /** CWE-772: Missing Release of Resource after Effective Lifetime */
    MISSING_RELEASE_OF_RESOURCE(772),

    /**
     * CWE-776: Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')
     */
    XML_ENTITY_EXPANSION(776),

    /** CWE-778: Insufficient Logging */
    INSUFFICIENT_LOGGING(778),

    /** CWE-780: Use of RSA Algorithm without OAEP */
    RSA_MISSING_PADDING(780),

    /** CWE-783: Operator Precedence Logic Error */
    OPERATOR_PRECEDENCE_LOGIC(783),

    /**
     * CWE-784: Reliance on Cookies without Validation and Integrity Checking in a Security Decision
     */
    RELIANCE_ON_UNCHECKED_COOKIE(784),

    /** CWE-789: Memory Allocation with Excessive Size Value */
    EXCESSIVE_SIZE_MEMORY_ALLOCATION(789),

    /** CWE-798: Use of Hard-coded Credentials */
    HARDCODED_CREDENTIALS(798),

    /** CWE-807: Reliance on Untrusted Inputs in a Security Decision */
    RELIANCE_IN_UNTRUSTED_INPUT(807),

    /** CWE-829: Inclusion of Functionality from Untrusted Control Sphere */
    INCLUDE_CODE_FROM_UNTRUSTED_SOURCE(829),

    /** CWE-835: Loop with Unreachable Exit Condition ('Infinite Loop') */
    LOOP_WITH_UNREACHABLE_EXIT(835),

    /** CWE-915: Improperly Controlled Modification of Dynamically-Determined Object Attributes */
    IMPROPER_CHECK_FOR_MODIFICATION(915),

    /** CWE-918: Server-Side Request Forgery (SSRF) */
    SERVER_SIDE_REQUEST_FORGERY(918),

    /** CWE CATEGORY: OWASP Top Ten 2013 Category A5 - Security Misconfiguration */
    CATEGORY_OWASP_2013_A5(933),

    /**
     * CWE-937: CWE CATEGORY: OWASP Top Ten 2013 Category A9 - Using Components with Known
     * Vulnerabilities
     */
    CATEGORY_OWASP_2013_A9(937),

    /** CWE-943: Improper Neutralization of Special Elements in Data Query Logic */
    IMPROPER_DATA_QUERY_NEUTRALIZATION(943),

    /** CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag */
    COOKIE_WITHOUT_HTTPONLY(1004),

    /** CWE-1021: Improper Restriction of Rendered UI Layers or Frames */
    IMPROPER_RESTRICTION_OF_UI_LAYERS(1021),

    /** CWE-1275: Sensitive Cookie with Improper SameSite Attribute */
    SENSITIVE_COOKIE_WITH_IMPROPER_SAMESITE_ATTR(1275);

    int number;

    CweNumber(int number) {
        this.number = number;
    }

    public static CweNumber lookup(int searchFor) {
        for (CweNumber entry : CweNumber.class.getEnumConstants()) {
            if (entry.number == searchFor) {
                return entry;
            }
        }

        System.out.println("WARN: Requested unmapped CWE number " + searchFor + ".");

        return DONTCARE;
    }

    public static CweNumber lookup(String searchFor) {
        try {
            return lookup(Integer.parseInt(searchFor));
        } catch (NumberFormatException n) {
            System.out.println("ERROR: Failed to parse CWE number '" + searchFor + "'.");
            return CweNumber.DONTCARE;
        }
    }
}
