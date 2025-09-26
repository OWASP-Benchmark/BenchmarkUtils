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
 * @author Dave Wichers
 * @created 2025
 */
package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.json.JSONObject;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;

public class ReSharperReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.isJson()
                && resultFile.line(1).contains("schemastore.azurewebsites.net")
                && resultFile.json().has("runs");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        TestSuiteResults tr =
                new TestSuiteResults("ReSharper", false, TestSuiteResults.ToolType.SAST);

        JSONArray runs = resultFile.json().getJSONArray("runs");
        JSONArray results = runs.getJSONObject(0).getJSONArray("results");
        // tr.setToolVersion(resultFile.json().getString("version"));

        // results
        for (int i = 0; i < results.length(); i++) {
            TestCaseResult tcr = parseReSharperFindings(results.getJSONObject(i));
            if (tcr != null) {
                tr.put(tcr);
            }
        }
        return tr;
    }

    private TestCaseResult parseReSharperFindings(JSONObject result) {
        try {
            String ruleId = result.getString("ruleId"); // Name of rule
            String level =
                    result.getString("level"); // Severity level of finding (note, warning, ...)
            String ruleExplanation = result.getJSONObject("message").getString("text");

            String uri =
                    result.getJSONArray("locations")
                            .getJSONObject(0)
                            .getJSONObject("physicalLocation")
                            .getJSONObject("artifactLocation")
                            .getString("uri");

            // String className = result.getString("filename");
            // className = (className.substring(className.lastIndexOf('/') +
            // 1)).split("\\.")[0];
            if (isTestCaseFile(uri)) {
                TestCaseResult tcr = new TestCaseResult();
                tcr.setActualResultTestID(TestSuiteResults.getFileNameNoPath(uri));

                // Figure out CWE
                int cweNum = cweLookup(ruleId, level, ruleExplanation, uri);
                if (cweNum != CweNumber.DONTCARE) {
                    tcr.setCWE(cweNum);
                    return tcr;
                }
            }

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    /**
     * This method maps ReSharper rules to their corresponding CWE, or CweNumber.DONTCARE, if we
     * don't care about it.
     */
    private int cweLookup(
            String ruleid, String severityLevel, String ruleExplanation, String filename) {
        switch (ruleid) {
            case "ArrangeModifiersOrder": // Inconsistent modifiers declaration order
            case "CheckNamespace": // Namespace does not correspond to file location
            case "ClassNeverInstantiated.Global": // Class 'FOO' is never instantiated
            case "CollectionNeverQueried.Local": // Content of collection 'FOO' is only updated but
                // never used
            case "ConvertIfStatementToConditionalTernaryExpression": // Convert into '?:' expression
            case "ConvertIfStatementToNullCoalescingExpression": // Convert into '??' expression
            case "FieldCanBeMadeReadOnly.Local": // Field can be made readonly
            case "ForCanBeConvertedToForeach": // For-loop can be converted into foreach-loop
            case "InconsistentNaming": // Name 'FOO' does not match rule 'Static readonly fields
                // (private)'
            case "JoinDeclarationAndInitializer": // Join declaration and assignment
            case "PossibleIntendedRethrow": // Exception rethrow possibly intended
            case "RedundantNameQualifier": // Qualifier is redundant
            case "RedundantUsingDirective": // Using directive not required and can be safely
            case "RedundantVerbatimStringPrefix": // Redundant verbatim string prefix
                // removed
            case "TooWideLocalVariableScope": // Local variable 'FOO' can be declared in inner scope
            case "UnassignedReadonlyField.Compiler": // Readonly field 'FOO' is never assigned
            case "UnusedMemberInSuper.Global": // Only overrides of method 'FOO' are used
            case "UnusedType.Global": // Class is never used
            case "UseObjectOrCollectionInitializer": // Use object or collection initializer (to
                // improve readability)
            case "UseStringInterpolation": // Use string interpolation expression
                return CweNumber.DONTCARE;

            case "AssignNullToNotNullAttribute": // Possible 'null' assignment to non-nullable
            case "ExpressionIsAlwaysNull": // Expression is always null
            case "PossibleNullReferenceException": // Possible 'System.NullReferenceException'
                // entity
            case "ReplaceWithStringIsNullOrEmpty": // Replace with '!String.IsNullOrEmpty'
                return 476; // CWE-476: NULL Pointer Dereference
            case "ConditionIsAlwaysTrueOrFalse":
                {
                    if ("Expression is always false".equals(ruleExplanation))
                        return 570; // CWE-570 Expression is Always False
                    else if ("Expression is always true".equals(ruleExplanation))
                        return 571; // CWE-571 Expression is Always True
                    else {
                        System.err.println(
                                "WARNING: Unmapped rule explanation of '"
                                        + ruleExplanation
                                        + "' for ruleid id: ConditionIsAlwaysTrueOrFalse");
                    }
                } // Intentionally fall thru to EqualExpressionComparison
            case "EqualExpressionComparison": // Similar expressions comparison
                return 571; // // CWE-571 Expression is Always True

            case "BadChildStatementIndent": // Line indent is not restored to the previous level
                // around child statement
            case "CSharpWarnings::CS0642": // Possible mistaken empty statement
            case "MisleadingBodyLikeStatement": // Statement can be confused with previous
                // statement's body
                return 483; // CWE-483 Incorrect Block Delimitation

            case "CSharpWarnings::CS0162": // Code is unreachable
            case "EmptyForStatement": // Empty 'for' loop is redundant
            case "EmptyStatement": // Empty statement is redundant
            case "HeuristicUnreachableCode": // Case/Code is heuristically unreachable
            case "MathAbsMethodIsRedundant": // Math.Abs() argument is always non-negative
            case "RedundantBoolCompare": // Comparison with true is redundant
            case "RedundantCast": // Type cast is redundant
            case "RedundantDefaultMemberInitializer": // Initializing field by default value is
            case "RedundantJumpStatement": // Redundant control flow jump statement
            case "RedundantStringFormatCall": // Redundant 'String.Format()' call
                // redundant
            case "UnusedField.Compiler": // Field 'FOO' is never used
            case "UnusedMember.Global": // Constant/Field/Method 'FOO' is never used
            case "UnusedMember.Local": // Constant/Field/Method 'FOO' is never used
            case "UselessBinaryOperation": // Addition or subtraction of 0 in every execution path,
                // which is useless
                return 561; // CWE-561 Dead Code

            case "CSharpWarnings::CS0618": // 'CS0618: Constructor
                // 'System.Net.Sockets.TcpListener.TcpListener(int)' is
                // obsolete: 'This method has been deprecated. Please use
                // TcpListener(IPAddress localaddr, int port) instead.
                // http://go.microsoft.com/fwlink/?linkid=14202'
                return 477; // CWE-477 Use of Obsolete Function
            case "CSharpWarnings::CS0665": // Assignment in conditional expression; did you mean to
                // use '==' instead of '='?
                return 481; // CWE-481 Assigning instead of Comparing

            case "CSharpWarnings::CS1717": // Assignment made to same variable; did you mean to
                // assign something else?
                return 481; // CWE-481 Assigning instead of Comparing

            case "FormatStringProblem": // Formatting is specified, but the argument is not
                // 'IFormattable'
                return 440; // CWE-440 Expected Behavior Violation
            case "FunctionNeverReturns": // Function never returns
                return 770; // CWE-770 Allocation of Resources Without Limits or Throttling
            case "FunctionRecursiveOnAllPaths": // Method is recursive on all execution paths
                return 674; // CWE-674 Uncontrolled Recursion
            case "InconsistentOrderOfLocks": // The expression is used in several lock statements
                // with inconsistent execution order, forming a cycle
                return 833; // CWE-833 Deadlock
            case "IntDivisionByZero": // Division by zero in at least one execution path
                return 369; // CWE-369 Divide by Zero
            case "IntVariableOverflowInUncheckedContext": // Possible overflow in unchecked context
                return 190; // CWE-190 Integer Overflow or Wraparound

            case "MemberCanBePrivate.Global": // Method 'FOO' can be made private
            case "MemberCanBeProtected.Global": // Method 'FOO' can be made protected
                return 668; // CWE-668 Exposure of Resource to Wrong Sphere

            case "NotAccessedField.Compiler": // Field 'FOO' is assigned but its value is never used
            case "NotAccessedVariable": // Local variable 'data' is only assigned but its value is
                // never used
            case "NotAccessedVariable.Compiler": // Local variable 'FOO' is assigned but its value
                // is never used
            case "RedundantAssignment": // Value assigned is not used in any execution path
            case "RedundantToStringCall": // Redundant 'Object.ToString()' call
            case "StructuredMessageTemplateProblem": // Argument is not used in message template
            case "UnusedParameter.Global": // Parameter 'FOO' is never used
            case "UnusedParameter.Local": // Parameter 'FOO' is never used
            case "UnusedVariable": // Local variable 'FOO' is never used
            case "UnusedVariable.Compiler": // Local variable 'FOO' is never used
                return 563; // CWE-563 Assignment to Variable without Use

            case "ReturnValueOfPureMethodIsNotUsed": // Return value of pure method is not used
                return 252; // CWE-252 Unchecked Return Value
            case "SuspiciousTypeConversion.Global": // Suspicious comparison: there is no type in
                // the solution which is inherited from both
                // 'System.Net.IPHostEntry' and 'string'
                return 510; // CWE-510 Trapdoor
            default:
                System.err.println(
                        "WARNING: no CWE value provided for ruleid id: '"
                                + ruleid
                                + "' with rule explanation: '"
                                + ruleExplanation
                                + "' and severity: '"
                                + severityLevel
                                + "' for file: "
                                + TestSuiteResults.getFileNameNoPath(filename));
        }
        return CweNumber.UNMAPPED;
    }
}
