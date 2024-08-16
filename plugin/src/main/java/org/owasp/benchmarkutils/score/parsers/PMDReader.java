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
        // System.out.println(
        //        "DRW: " + violationNodes.size() + " potential violations for file: " + testclass);
        if (isTestCaseFile(testclass)) {
            // System.out.println("DRW: " + testclass + " is test case file.");
            for (Node violationNode : violationNodes) {

                TestCaseResult tcr = new TestCaseResult();
                tcr.setActualResultTestID(testclass);
                String violation =
                        violationNode.getAttributes().getNamedItem("rule").getNodeValue();
                // System.out.println("DRW: looking up CWE for rule: " + violation);
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
            case "AvoidDuplicateLiterals":
            case "AvoidFileStream":
            case "AvoidInstantiatingObjectsInLoops":
            case "AvoidLiteralsInIfCondition":
            case "AvoidReassigningParameters":
            case "AvoidStringBufferField":
            case "AvoidUsingHardCodedIP":
            case "AvoidUsingNativeCode":
            case "AvoidUsingOctalValues":
            case "ClassNamingConventions":
            case "ClassWithOnlyPrivateConstructorsShouldBeFinal":
            case "CloneMethodMustBePublic":
            case "CollapsibleIfStatements":
            case "CognitiveComplexity":
            case "CommentDefaultAccessModifier": // What is this?
            case "ConfusingTernary":
            case "ControlStatementBraces":
            case "CyclomaticComplexity":
            case "EmptyCatchBlock":
            case "EmptyControlStatement":
            case "EmptyFinallyBlock":
            case "EmptyStatementNotInLoop":
            case "EmptySwitchStatements":
            case "ExceptionAsFlowControl":
            case "FieldDeclarationsShouldBeAtStartOfClass":
            case "FieldNamingConventions":
            case "GuardLogStatement":
            case "IdenticalCatchBranches":
            case "ImmutableField": // One of the static/final but not Immutable CWEs?
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
            case "NcssCount": // What is this?
            case "NonStaticInitializer":
            case "NPathComplexity":
            case "OnlyOneReturn":
            case "OverrideBothEqualsAndHashcode":
            case "PackageCase":
            case "RedundantFieldInitializer":
            case "ReplaceVectorWithList":
            case "ShortClassName":
            case "ShortVariable":
            case "SwitchDensity":
            case "SystemPrintln":
            case "TestClassWithoutTestCases":
            case "TooFewBranchesForASwitchStatement":
            case "TooManyMethods":
            case "UnnecessaryAnnotationValueElement":
            case "UnnecessaryBoxing":
            case "UnusedAssignment":
            case "UnnecessaryCast":
            case "UnnecessaryConversionTemporary":
            case "UnnecessaryFullyQualifiedName":
            case "UnnecessaryImport":
            case "UnnecessaryLocalBeforeReturn":
            case "UnnecessaryModifier":
            case "UnnecessaryReturn":
            case "UnnecessarySemicolon":
            case "UnusedImports":
            case "UnusedPrivateField":
            case "UnusedPrivateMethod":
            case "UseDiamondOperator":
            case "UseArrayListInsteadOfVector":
            case "UselessOperationOnImmutable":
            case "UselessParentheses":
            case "UselessStringValueOf":
            case "UseLocaleWithCaseConversions":
            case "UseShortArrayInitializer":
            case "UseTryWithResources": // CWE 772?
            case "UseUnderscoresInNumericLiterals":
            case "UseVarargs":
                return CweNumber.DONTCARE;

                /*/ Some of these might map to CWEs
                case "DoNotThrowExceptionInFinally":
                case "LiteralsFirstInComparisons": // CWE for NullPointer?
                case "PrematureDeclaration": // ???
                case "UseIndexOfChar":
                case "UseProperClassLoader":
                    return CweNumber.DONTCARE;*/

                // Are these the CWE for Expression Always True or False?
            case "EmptyIfStmt":
            case "UnconditionalIfStatement":
                return CweNumber.DONTCARE;

            case "AvoidPrintStackTrace":
                return 209;

            case "AvoidThrowingRawExceptionTypes":
                return 248;

            case "HardCodedCryptoKey":
                return 321;

            case "DoNotTerminateVM":
                return 382;
            case "DoNotUseThreads":
                return 383;
            case "AvoidCatchingNPE":
                return 395;

            case "AvoidCatchingGenericException":
            case "AvoidCatchingThrowable":
                return 396;

            case "IdempotentOperations":
                return 398;

            case "CloseResource":
                return 400;

            case "BrokenNullCheck":
            case "NullAssignment":
                return 476;

            case "SwitchStmtsShouldHaveDefault":
                return 478;

            case "OneDeclarationPerLine":
                return 483;
            case "ImplicitSwitchFallThrough":
                return 484;

            case "UnusedFormalParameter":
            case "UnusedLocalVariable":
                return 563;

            case "FinalizeDoesNotCallSuperFinalize":
                return 568;

            case "DontCallThreadRun":
                return 572;

            case "ProperCloneImplementation":
                return 580;

            case "ReturnFromFinallyBlock":
                return 584;

            case "AvoidCallingFinalize":
                return 586;

            case "CompareObjectsWithEquals":
            case "UseEqualsToCompareStrings":
                return 597;

            case "MutableStaticState":
                return 607; // Or 582?

                // Should any of these be 609??
                // case "AvoidSynchronizedAtMethodLevel":
                // case "DoNotUseThreads":
                // case "NonThreadSafeSingleton":
            case "DoubleCheckedLocking":
                return 609;

                // Don't think PMD reports any of these:
            case "??1":
                return CweNumber.INSECURE_COOKIE;
            case "??2":
                return CweNumber.WEAK_RANDOM;
            case "??3":
                return CweNumber.LDAP_INJECTION;
            case "??4":
                return CweNumber.PATH_TRAVERSAL;
            case "??5":
                return CweNumber.PATH_TRAVERSAL;
            case "??6":
                return CweNumber.WEAK_CRYPTO_ALGO;
            case "??7":
                return CweNumber.XPATH_INJECTION;
            case "??8":
                return CweNumber.WEAK_HASH_ALGO;
            case "??9":
                return CweNumber.COMMAND_INJECTION;
            case "??10":
                return CweNumber.XSS;

                // FbInfer additional rules
            case "RESOURCE_LEAK":
            case "NULL_DEREFERENCE":
                return CweNumber.DONTCARE;

            default:
                System.out.println(
                        "WARNING: Unknown PMD vuln category: "
                                + rule
                                + " for test case: "
                                + testclass);
        }

        return CweNumber.UNKNOWN;
    }
}
