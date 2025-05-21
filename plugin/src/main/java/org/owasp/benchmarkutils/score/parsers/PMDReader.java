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
 * @created 2015
 */
package org.owasp.benchmarkutils.score.parsers;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.List;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.owasp.benchmarkutils.score.CweNumber;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestCaseResult;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

public class PMDReader extends Reader {

    @Override
    public boolean canRead(ResultFile resultFile) {
        return resultFile.filename().endsWith(".xml") && resultFile.xmlRootNodeName().equals("pmd");
    }

    @Override
    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();
        // Prevent XXE
        docBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder docBuilder = docBuilderFactory.newDocumentBuilder();
        InputSource is = new InputSource(new FileInputStream(resultFile.file()));
        Document doc = docBuilder.parse(is);

        TestSuiteResults tr = new TestSuiteResults("PMD", false, TestSuiteResults.ToolType.SAST);

        // If the filename includes an elapsed time in seconds (e.g., TOOLNAME-seconds.xml), set the
        // compute time on the scorecard.
        tr.setTime(resultFile.file());

        Node root = doc.getDocumentElement();
        String version = getAttributeValue("version", root);

        NodeList rootList = root.getChildNodes();
        tr.setToolVersion(version);

        List<Node> fileNodesList = getNamedNodes("file", rootList);

        for (Node fileNode : fileNodesList) {
            List<TestCaseResult> tcrs = parsePMDItem(fileNode);
            for (TestCaseResult tcr : tcrs) {
                tr.put(tcr);
            }
        }

        return tr;
    }

    private List<TestCaseResult> parsePMDItem(Node fileNode) {
        List<TestCaseResult> results = new ArrayList<TestCaseResult>();
        String filename = fileNode.getAttributes().getNamedItem("name").getNodeValue();

        List<Node> violationNodes = getNamedChildren("violation", fileNode);
        String testclass = filename.substring(filename.lastIndexOf(File.separator) + 1);
        if (isTestCaseFile(testclass)) {
            for (Node violationNode : violationNodes) {

                TestCaseResult tcr = new TestCaseResult();
                tcr.setActualResultTestID(testclass);
                String violation =
                        violationNode.getAttributes().getNamedItem("rule").getNodeValue();
                tcr.setCWE(figureCWE(violation, testclass));
                tcr.setEvidence(violation);
                results.add(tcr);
            }
        }
        return results;
    }

    private int figureCWE(String rule, String testclass) {
        switch (rule) {
            case "AddEmptyString":
            case "AtLeastOneConstructor":
            case "AvoidBranchingStatementAsLastInLoop":
            case "AvoidDeeplyNestedIfStmts":
            case "AvoidDuplicateLiterals": // Semi-replacement for AvoidFinalLocalVariable
            case "AvoidFileStream":
            case "AvoidFinalLocalVariable": // Deprecated PMD rule. No replacement.
            case "AvoidInstantiatingObjectsInLoops":
            case "AvoidLiteralsInIfCondition":
            case "AvoidPrefixingMethodParameters": // Deprecated PMD rule, replaced with
                // FormalParameterNamingConventions
            case "AvoidStringBufferField":
            case "AvoidUsingOctalValues":
            case "AvoidUsingShortType": // Deprecated PMD rule. No replacement.
            case "AvoidUsingVolatile":
            case "BeanMembersShouldSerialize": // Deprecated PMD rule, replaced with
                // NonSerializableClass
            case "ClassNamingConventions":
            case "ClassWithOnlyPrivateConstructorsShouldBeFinal":
            case "CloneMethodMustBePublic":
            case "CollapsibleIfStatements":
            case "CognitiveComplexity":
            case "CommentDefaultAccessModifier": // Replacement for DefaultPackage
            case "ConfusingTernary":
            case "ConsecutiveAppendsShouldReuse":
            case "CyclomaticComplexity":
            case "DefaultPackage": // Deprecated PMD rule, replaced with
                // CommentDefaultAccessModifier
            case "DuplicateImports": // Deprecated PMD rule, replaced with Unnecessary Import
            case "EmptyFinallyBlock": // Deprecated PMD rule, replaced with EmptyControlStatement
            case "EmptySwitchStatements": // Deprecated PMD rule, replaced with
                // EmptyControlStatement
            case "ExceptionAsFlowControl":
            case "ExcessiveMethodLength": // Deprecated PMD rule, use NcssCount instead
            case "FieldDeclarationsShouldBeAtStartOfClass":
            case "ForLoopCanBeForeach":
            case "FormalParameterNamingConventions":
            case "GodClass":
            case "IdenticalCatchBranches":
            case "ImmutableField": // One of the static/final but not Immutable CWEs?
            case "InsufficientStringBufferDeclaration":
            case "LawOfDemeter": // Principal of Least Knowledge
            case "LinguisticNaming":
            case "LocalVariableCouldBeFinal":
            case "LocalVariableNamingConventions":
            case "LongVariable":
            case "LooseCoupling":
            case "MethodArgumentCouldBeFinal":
            case "MethodNamingConventions":
            case "MissingOverride":
            case "MissingSerialVersionUID":
            case "MoreThanOneLogger":
            case "NcssCount": // Generates non-commenting source statements (NCSS) metrics
            case "NonThreadSafeSingleton":
            case "NonStaticInitializer":
            case "NPathComplexity":
            case "OneDeclarationPerLine":
            case "OnlyOneReturn":
            case "PackageCase":
            case "PrematureDeclaration":
            case "RedundantFieldInitializer":
            case "ReplaceHashtableWithMap":
            case "ReplaceVectorWithList":
            case "ShortClassName":
            case "ShortVariable":
            case "SimplifyBooleanReturns":
            case "SwitchDensity":
            case "SystemPrintln":
            case "TestClassWithoutTestCases":
            case "TooFewBranchesForASwitchStatement":
            case "TooFewBranchesForSwitch":
            case "TooManyMethods":
            case "UnnecessaryAnnotationValueElement":
            case "UnnecessaryBoxing":
            case "UnnecessaryCast":
            case "UnnecessaryConversionTemporary":
            case "UnnecessaryFullyQualifiedName":
            case "UnnecessaryImport":
            case "UnnecessaryLocalBeforeReturn":
            case "UnnecessaryModifier":
            case "UnnecessaryReturn":
            case "UnusedImports":
            case "UseArrayListInsteadOfVector":
            case "UseDiamondOperator":
            case "UseIndexOfChar":
            case "UselessOperationOnImmutable":
            case "UselessParentheses":
            case "UselessStringValueOf":
            case "UseLocaleWithCaseConversions":
            case "UseProperClassLoader":
            case "UseShortArrayInitializer":
                // Use Try w/Resources doesn't necessarily mean: CWE 772: Missing Release of
                // Resource after Effective Lifetime
            case "UseTryWithResources":
            case "UseUnderscoresInNumericLiterals":
            case "UseUtilityClass":
            case "UseVarargs":
            case "VariableNamingConventions": // Deprecated PMD rule, replaced w/ 3x more specific
                // rules
                return CweNumber.DONTCARE;

            case "AvoidUsingNativeCode":
                return 111; // Direct Use of Unsafe JNI

            case "AvoidPrintStackTrace":
                return 209; // Generation of Error Msg Containing Sensitive Info

            case "HardCodedCryptoKey":
                return 321; // Use of Hard-coded Crypto Key
            case "InsecureCryptoIv":
                return 329; // Generate Predictable IV with CBC Mode

            case "DoNotCallSystemExit": // Deprecated PMD rule, renamed to DoNotTerminateVM
            case "DoNotTerminateVM":
                return 382; // Use of System.exit()
            case "DoNotUseThreads":
                return 383; // Direct Use of Threads

            case "EmptyIfStmt": // Deprecated PMD rule, replaced with EmptyControlStatement
            case "EmptyCatchBlock":
                return 390; // Detection of Error Condition w/out Action
            case "AvoidCatchingNPE":
                return 395; // Use of NPE Catch to Detect NULL Pointer Dereference

            case "AvoidCatchingGenericException":
            case "AvoidCatchingThrowable":
                return 396; // Declaration of Catch for Generic Exception

            case "AvoidThrowingRawExceptionTypes":
            case "SignatureDeclareThrowsException":
                return 397; // Declaration of Throws for Generic Exception

            case "EmptyControlStatement":
            case "EmptyStatementBlock": // Deprecated PMD rule, replaced with EmptyControlStatement
            case "EmptyWhileStmt": // Deprecated PMD rule, replaced with EmptyControlStatement
            case "EmptyStatementNotInLoop": // Deprecated PMD rule, replaced w/ UnnecessarySemicolon
            case "IdempotentOperations":
            case "UnnecessarySemicolon":
                return 398; // Code Quality - prohibited mapping category

            case "RESOURCE_LEAK": // FbInfer Additional rule
                return 400; // Uncontrolled Resource Consumption

            case "CloseResource":
                return 404; // Improper Resource Shutdown or Release

            case "BrokenNullCheck":
            case "LiteralsFirstInComparisons":
            case "NullAssignment":
            case "NULL_DEREFERENCE": // FbInfer Additional rule
            case "PositionLiteralsFirstInComparisons": // Replaced by LiteralsFirstInComparisons
                return 476; // NULL Pointer Dereference

            case "NonExhaustiveSwitch":
            case "SwitchStmtsShouldHaveDefault":
                return 478; // Missing Default Case in Multiple Condition Expression

            case "AssignmentInOperand":
                return 481; // Assigning instead of Comparing

            case "SimplifyBooleanExpressions":
                return 482; // Comparing Instead of Assigning

            case "IfStmtsMustUseBraces": // Deprecated PMD Rule, replaced by ControlStatementBraces
            case "ControlStatementBraces":
                return 483; // Incorrect Block Delimitation

            case "ImplicitSwitchFallThrough":
            case "MissingBreakInSwitch": // Deprecated: replaced by ImplicitSwitchFallThrough
                return 484; // Omitted Break Statement in Switch

            case "CloneMethodReturnTypeMustMatchClassName":
                return 491; // Public cloneable Method without Final (Object Hijack)

            case "FieldNamingConventions":
            case "SuspiciousConstantFieldName": // Deprecated: replaced by FieldNamingConventions
                return 500; // Pub Static Field Not Marked Final

            case "AvoidAccessibilityAlteration":
                return 506; // Embedded Malicious Code
            case "AvoidUsingHardCodedIP":
                return 510; // Trapdoor, child of CWE-506: Malicious Code
            case "GuardLogStatement":
                return 532; // Info Exposure Through Server Log Files

            case "UnusedPrivateMethod":
                return 561; // Dead Code

            case "AvoidReassigningParameters":
            case "DataflowAnomalyAnalysis": // Deprecated: replaced by UnusedAssignment
            case "SingularField":
            case "UnusedAssignment":
            case "UnusedFormalParameter":
            case "UnusedLocalVariable":
            case "UnusedPrivateField":
                return 563; // Unused Variable

            case "EmptyFinalizer":
            case "FinalizeDoesNotCallSuperFinalize":
                return 568; // finalize() without super.finalize()

                // CWE 570 is Expression Always False - 571 is Expression Always True
                // Return parent of 570, 571, since this doesn't distinguish between them
            case "UnconditionalIfStatement":
                return 710; // Improper Adherence to Coding Standards

            case "DontCallThreadRun":
                return 572; // Call to Thread run() instead of start()

            case "ProperCloneImplementation":
                return 580;
            case "OverrideBothEqualsAndHashcode":
                return 581;
            case "ReturnFromFinallyBlock":
                return 584; // Return Inside Finally Block
            case "DoNotThrowExceptionInFinally": // Has same effect as ReturnFromFinallyBlock
                return 705; // Incorrect Control Flow Scoping (parent of 584)

            case "EmptySynchronizedBlock": // Deprecated: replaced by EmptyControlStatement
                return 585; // Empty Synchronized Block
            case "AvoidCallingFinalize":
                return 586; // Explicit Call to Finalize()

            case "CompareObjectsWithEquals":
            case "UseEqualsToCompareStrings":
                return 597; // Use of Wrong Operator in String Comparison

            case "MutableStaticState":
                return 607; // Pub Stat Final Field References Mutable Object - could also be
                // 582-Array Declared Public, Final, Static

            case "DoubleCheckedLocking":
                return 609; // Double-Checked Locking

            case "AvoidSynchronizedAtMethodLevel":
            case "AvoidSynchronizedStatement":
                return 833; // Deadlock

            case "WhileLoopWithLiteralBoolean":
                return 835; // While True

            default:
                System.out.println(
                        "WARNING: Unknown PMD vuln category: "
                                + rule
                                + " for test case: "
                                + testclass);
        }

        return CweNumber.UNMAPPED;
    }
}
