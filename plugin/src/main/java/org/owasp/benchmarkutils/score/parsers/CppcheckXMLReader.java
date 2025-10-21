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

import java.util.List;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Node;

/**
 * The Cppcheck XML reader parses the XML results file generated when you use the cppcheck analyzer
 * to analyze then export results to an XML file. The command is like: cppcheck . --enable=all --xml
 * 2> YOURFILENAME.xml. Other parameters are likely required to include support files (-I), or
 * possibly exclude certain source files (-i).
 */
public class CppcheckXMLReader extends Reader {

    private boolean bugHuntingRulesEnabled =
            false; // If set, causes BugHunting to be added to toolname

    @Override
    public boolean canRead(ResultFile resultFile) {
        /*
         * XML file starts with:
         *    <?xml version="1.0" encoding="UTF-8"?>
         *      <results version="2">
         *        <cppcheck version="2.18.0" />
         *        <errors>
         *          <error id= ...
         *
         * while older versions look like this:
         *    <?xml version="1.0" encoding="UTF-8"?>
         *      <results>
         *         <error file="CWE244_Heap_Inspection__w32_char_free_03.c" line="54" id="knownConditionTrueFalse" severity="style" msg="Condition &apos;5!=5&apos; is always false"/>
         */
        return resultFile.filename().endsWith(".xml")
                && (resultFile.line(2).contains("cppcheck")
                        || resultFile.line(3).contains("<error file=\""));
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        boolean legacyFormat =
                false; // Set to true if using the OLD cppcheck XML that doesn't include cppcheck
        // name or version number
        TestSuiteResults tr =
                new TestSuiteResults("Cppcheck", true, TestSuiteResults.ToolType.SAST);

        // get and parse: <cppcheck version="2.9" />
        String version = "legacy";
        Node cppcheck = getNamedChild("cppcheck", resultFile.xmlRootNode());
        legacyFormat = (cppcheck == null);
        if (!legacyFormat) {
            version = getAttributeValue("version", cppcheck);

            // Check to see if this is Cppcheck Premium. If so, set the name
            String productName = getAttributeValue("product-name", cppcheck);
            if (productName != null)
                // Strip out all white space from name
                tr.setTool(productName.replaceAll("\\s+", ""));
        }
        tr.setToolVersion(version);

        Node errorsNode =
                (legacyFormat
                        ? resultFile.xmlRootNode()
                        : getNamedChild("errors", resultFile.xmlRootNode()));
        List<Node> errors = getNamedChildren("error", errorsNode);

        // Used to track the number of files that can't be analyzed by the MISRA rules properly
        int internalErrorCount = 0;
        // Used to track the number of files that can't be analyzed because of a MISRA config issue
        int misraConfigIssueCount = 0;

        for (Node error : errors) {
            TestCaseResult tcr = new TestCaseResult();
            String filename =
                    (legacyFormat
                            ? getAttributeValue("file", error)
                            : getAttributeValue("file0", error));

            // There are some rules where the file location is not specified directly in the
            // filename attribute
            if (filename == null) {
                String ruleid = getAttributeValue("id", error);
                switch (ruleid) {
                    case "ctunullpointer":
                    case "unusedFunction":
                        // For these rules, the file location is specified in a child node like
                        // this: <location
                        // file="testcases/CWE476_NULL_Pointer_Dereference/CWE476_NULL_Pointer_Dereference__char_41.c" line="28" column="22" info="Dereferencing argument data that is null"/>

                        Node locationNode = getNamedChild("location", error);
                        filename = getAttributeValue("file", locationNode);
                        if (filename == null) {
                            continue; // Skip to next error Node in for loop since finding is mapped
                            // to specific file.
                        }

                        // Drop through to if (isTestCaseFile(filename)) below
                        break;

                        // Check to see if is an 'information' level error like:  error:
                        // id="missingIncludeSystem" severity="information" msg="Include file:
                        // &lt;stdio.h&gt; not found. Please note: Cppcheck does not need standard
                        // library headers to get proper results."

                        // If so, don't generate a warning message
                    case "checkersReport":
                    case "missingIncludeSystem": // Had to add
                        // case "toomanyconfigs": // Have to add --force to command to address
                        // id="toomanyconfigs" severity="information" msg="Too many #ifdef
                        // configurations - cppcheck only checks 12 of 19 configurations. Use
                        // --force to check all configurations."
                        continue; // Skip to next error Node in for loop

                    default:
                        /* System.out.println(
                        "DRW: Node has no 'file0' attribute: "
                                + error
                                + " but has ruleid: "
                                + ruleid); */
                        continue; // Skip to next error Node in for loop
                }
            }

            if (isTestCaseFile(filename)) {
                tcr.setActualResultTestID(TestSuiteResults.getFileNameNoPath(filename));
                String cwe = getAttributeValue("cwe", error);

                // The following maps rules to CWE numbers if not specified in the Cppcheck rule
                if (cwe == null) {
                    // Most of these are from the legacy Cppcheck format which didn't include CWEs.
                    // Only a few in Cppcheck 2.9+ don't have CWEs specified.
                    String ruleid = getAttributeValue("id", error);
                    String ruleMsg = getAttributeValue("msg", error);
                    if ("misra-config".equals(ruleid)) misraConfigIssueCount++;
                    else {
                        int CWE = cweLookup(ruleid, ruleMsg, filename, internalErrorCount);
                        if (CWE != CweNumber.DONTCARE) {
                            tcr.setCWE(CWE);
                            tr.put(tcr);
                        }
                    }
                } else {
                    try {
                        /*
                        System.out.println(
                                "For rule: '"
                                        + getAttributeValue("id", error)
                                        + "', the Cppcheck provided CWE is: "
                                        + cwe); // DEBUG
                        */
                        tcr.setCWE(Integer.parseInt(cwe));
                        tr.put(tcr);
                    } catch (NumberFormatException e) {
                        String ruleid = getAttributeValue("id", error);
                        System.err.println(
                                "ERROR: error id: '"
                                        + ruleid
                                        + "' has non-integer CWE value of: "
                                        + cwe);
                    }
                }
            } else {
                // Do nothing. Skip results for non-test files.
            }
        }

        if (internalErrorCount > 0) {
            System.err.println(
                    "MISRA WARNING: This many source files reported an internalError so couldn't be analyzed by MISRA rules: "
                            + internalErrorCount);
        }
        if (misraConfigIssueCount > 0) {
            System.err.println(
                    "MISRA WARNING: This many source files reported a misra-config issue so couldn't be analyzed by MISRA rules: "
                            + misraConfigIssueCount);
        }

        // Before returning test results, check to see if bugHuntingRulesEnabled is enabled, and add
        // this to toolname
        if (bugHuntingRulesEnabled) {
            String toolname = tr.getToolName();
            tr.setTool(toolname += "_wBugHunting");
        }
        return tr;
    }

    /**
     * This method maps Cppcheck rule names to their corresponding CWE number, or -1, if we don't
     * care about it.
     */
    private int cweLookup(String ruleid, String ruleMsg, String filename, int internalErrorCount) {

        // Check to see if we've seen any premium-bughunting rule findings. If so, set this flag to
        // true, so BugHunting gets added to toolname
        if (!bugHuntingRulesEnabled && ruleid.startsWith("premium-bughunting"))
            bugHuntingRulesEnabled = true;

        switch (ruleid) {
                // These are all from Cppcheck 2.x+
            case "allocaCalled":
                // Currently, do nothing. Not inherently unsafe.
                // See: "Obsolete function 'alloca' called. In C99 and later
                // it is recommended to use a variable length array instead."
                // verbose="The obsolete function 'alloca' is called. In C99
                // and later it is recommended to use a variable length array or a
                // dynamically allocated array instead. The function 'alloca'
                // is dangerous for many reasons
                // (http://stackoverflow.com/questions/1018853/why-is-alloca-not-considered-good-practice and http://linux.die.net/man/3/alloca).
            case "missingOverride":
                // Means Override annotation missing when overriding a method.
            case "normalCheckLevelMaxBranches":
                // Limiting analysis of branches. Use --check-level=exhaustive to analyze all
                // branches
                return CweNumber.DONTCARE;
            case "overlappingWriteFunction":
                // Overlapping read/write in memcpy() is undefined behavior
                return 475; // CWE-475: Undefined Behavior for Input to API

                // These are all from legacy Cppcheck which didn't include CWE numbers
                // with rule findings:
            case "arrayIndexOutOfBounds": // MAPPED to 788 (DISCOURAGED)
            case "pointerOutOfBounds": // MAPPED to 758
                return 119; // CWE-119 (Improper Restriction of Operations within the
                // Bounds of a Memory Buffer)
            case "AssignmentIntegerToAddress": // Not found in 2.x
                return 758; // CWE-758: Reliance on Undefined, Unspecified, or
                // Implementation-Defined Behavior
            case "autovarInvalidDeallocation":
                return 590; // CWE-590: Use of a Pointer to an Invalid Location
            case "bufferAccessOutOfBounds":
                return 788; // CWE-788: Access of Memory Location After End of Buffer
            case "copyCtorAndEqOperator": // Not found in 2.x
                // The copyCtorAndEqOperator rule in Cppcheck is a built-in static
                // analysis rule that checks whether a class has both a copy constructor
                // and a copy assignment operator defined. This rule ensures that if one
                // of these is defined, the other should also be explicitly implemented
                // to avoid unintended behavior or inconsistencies in copying and
                // assignment operations.
                return 1098; // CWE-491 (Incomplete Copy with Insufficiently Defined Copy
                // Constructor or Assignment Operator)
            case "constStatement":
            case "cstyleCast":
            case "duplicateExpression":
            case "nullPointerRedundantCheck": // Mapped to 476
            case "operatorEqToSelf": // Should be to CWE-563: Assignment to Variable without Use?
            case "passedByValue":
            case "postfixOperator":
            case "selfAssignment":
            case "useInitializationList": // encourage the use of initialization lists in
                // C++ constructors
            case "variableScope": // style-related check that suggests reducing the scope of
                // variables
                return 398; // CWE-398: Indicator of Poor Code Quality
            case "deadpointer": // Not found in 2.x
                return 825; // CWE-825: Expired Pointer Dereference
            case "deallocret": // Detects cases where a function returns a
                // pointer to a resource that has already been deallocated
                return 672; // CWE-672: Operation on a Resource after Expiration or Release
            case "deallocDealloc": // Not found in 2.x
            case "doubleFree":
                return 415; // CWE-415: Double Free
            case "getsCalled":
                return 477; // CWE-477: (Obsolete Function)

                // This occurs when running the MISRA rules and there is an error parsing the file
            case "internalError":
                internalErrorCount++;
                return CweNumber.DONTCARE;

            case "invalidFunctionArg":
                return 628; // CWE-628: Function Call with Incorrectly Specified Arguments
            case "invalidPrintfArgType_int": // Not found in 2.x but does have
                // invalidPrintfArgType_uint
            case "invalidPrintfArgType_s":
            case "invalidScanfArgType_int": // Not found in 2.x
                return 686; // CWE-686: Function Call With Incorrect Argument Type

            case "knownConditionTrueFalse": // 2 other rules do 398 and 571
            case "staticStringCompare": // Not found in 2.x
            case "unsignedLessThanZero":
            case "unsignedPositive":
                return 570; // CWE-571: Expression is Always False
            case "memleak":
            case "memleakOnRealloc":
                return 401; // CWE-401 Improper Release of Memory Before Removing Last Reference
            case "mismatchAllocDealloc":
                return 762; // CWE-762: Mismatched Memory Management Routines
            case "mismatchSize": // Not found in 2.x
                return 131; // CWE-131: Incorrect Calculation of Buffer Size
            case "negativeIndex":
                return 786; // CWE-786: Access of Memory Location Before Start of Buffer
            case "negativeMemoryAllocationSize": // Not found in 2.x
                // Caused by Integer Overflow or Wraparound
                return 190; // CWE-190: Integer Overflow or Wraparound
            case "noCopyConstructor": // Mapped to 398
            case "noExplicitConstructor": // Mapped to 398
                return 1098; // CWE-1098: Data Element containing Pointer Item without Proper Copy
                // Control Element
            case "nullPointer":
                return 476; // CWE-476: NULL Pointer Dereference
            case "pointerSize":
                return 467; // CWE-467: Use of sizeof() on a Pointer Type
            case "redundantAssignment":
            case "unreadVariable":
            case "unusedStructMember":
            case "unusedVariable":
                return 563; // CWE-563: Assignment to Variable without Use

            case "resourceLeak": // Mapped to 775
                return 772; // CWE-772: Missing Release of Resource after Effective Lifetime
            case "signConversion":
                return 195; // https://cwe.mitre.org/data/definitions/195.html
            case "unassignedVariable":
                return 665; // CWE-665: Improper Initialization
            case "uninitdata":
            case "uninitMemberVar": // Mapped to 398
            case "uninitStructMember": // Not found in 2.x
            case "uninitvar":
                return 457; // CWE-457: Use of Uninitialized Variable
            case "unsafeClassCanLeak": // Mapped to 398
                return 401; // CWE-401: Improper Release of Memory Before Removing Last Reference
            case "duplicateBreak":
            case "unusedFunction":
                return 561; // CWE-561: Dead Code
            case "useClosedFile":
                return 910; // CWE-910 (Use of Expired File Descriptor or Handle)
            case "virtualDestructor":
                return 404; // CWE-404: Improper Resource Shutdown or Release
            case "wrongPrintfScanfArgNum":
                return 685; // CWE-685: Function Call With Incorrect Number of Arguments
            case "zerodiv":
                return 369; // CWE-369: Divide By Zero

                // CppCheck Premium Rules
            case "premium-reassignInLoop": // Reassigning 'FOO' in loop. Should loop variables be
                // used in expression?
                return 665; // CWE-665: Improper Initialization
            case "premium-unusedPrivateMember": // Private member data is assigned but not read
            case "premium-unreadVariable": // Variable 'FOO' is assigned a value that is never used
                return 563; // CWE-563: Assignment to Variable without Use
            case "premium-unusedVariable": // Unused variable: FOO
                return 561; // CWE-561: Dead Code
            case "premium-useAfterFree": // Attempt to use freed pointer 'FOO'
                return 416; // CWE-416: Use After Free

                // CppCheck Premium BugHunting Rules
            case "premium-bughuntingArrayIndexNegative": // Array index out of bounds, cannot
                // determine that FOO is not negative
            case "premium-bughuntingArrayIndexOutOfBounds": // Cannot determine that array index is
                // valid: foo[bar]
                return 129; // CWE-129 Improper Validation of Array Index
            case "premium-bughuntingBufferOverflow": // When calling 'wcscpy' it cannot be
                // determined that 1st argument is not overflowed
            case "premium-bughuntingPointerAdditionOverflow": // Cannot determine that pointer
                // addition can not overflow: data+dataLen
            case "premium-bughuntingPointerSubtractionOverflow": // Cannot determine that pointer
                // subtraction can not overflow: FOO
                return 119; // CWE-119 Improper Restriction of Operations within Bounds of Memory
                // Buffer
            case "premium-bughuntingUninit": // Cannot determine that 'FOO' is initialized
            case "premium-bughuntingUninitNonConstArg": // Cannot determine that 'FOO' is
                // initialized (since function parameter is not 'const' it is assumed it points at
                // uninitialized data)
                return 457; // Use of Uninitialized Variable

                // TODO: The MISEA mappings is massively incomplete. It is so huge that its
                // currently not worth the effort to do all the mappings, so while this incomplete
                // code is left in, its not even close to done.
                // These are all the MISRA specific findings:
            case "misra-c2012-8.2": // Function types shall be in prototype form with named
                // parameters
            case "misra-c2012-8.4": // A compatible declaration shall be visible when an object or
                // function with external linkage is defined
            case "misra-c2012-12.1": // The precedence of operators within expressions should be
                // made explicit
            case "misra-c2012-15.4": // There should be no more than one break or goto statement
                // used to terminate any iteration statement
            case "misra-c2012-17.3": // A function shall not be declared implicitly'
                return CweNumber.DONTCARE;

            case "misra-c2012-17.7": // The value returned by a function having non-void return type
                // shall be used
                return 252; // CWE-252 Unchecked Return Value

            default:
                /* DEBUG code to help map MISRA findings:
                if (ruleid.startsWith("misra-c")) {
                    String misraID = ruleid.substring("misra-c".length());
                    misraID = misraID.replace('-', '0');
                    misraID = misraID.replace('.', '0');
                    try {
                        return Integer.parseInt(misraID);
                    } catch (NumberFormatException e) {
                        System.err.println(
                                "WARNING: couldn't convert remaining MISRA ID to number: '"
                                        + misraID
                                        + "'");
                    }
                } else */
                System.err.println(
                        "WARNING: no CWE value provided for ruleid id: '"
                                + ruleid
                                + "' with message: '"
                                + ruleMsg
                                + "' for file: "
                                + TestSuiteResults.getFileNameNoPath(filename));
        }
        return CweNumber.UNMAPPED;
    }
}
