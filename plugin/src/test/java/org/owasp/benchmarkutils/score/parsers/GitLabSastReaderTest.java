package org.owasp.benchmarkutils.score.parsers;

import org.json.JSONArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.owasp.benchmarkutils.score.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GitLabSastReaderTest extends ReaderTestBase {

    private ResultFile resultFile;

    @BeforeEach
    void setUp() {
        resultFile = TestHelper.resultFileOf("testfiles/Benchmark_GitLab_SAST.json");
        BenchmarkScore.TESTCASENAME = "BenchmarkTest";
    }

    @Test
    public void onlyGitLabSastReaderReportsCanReadAsTrue() {
        assertOnlyMatcherClassIs(this.resultFile, GitLabSastReader.class);
    }

    @Test
    void readerHandlesGivenResultFile() throws Exception {
        GitLabSastReader reader = new GitLabSastReader();
        TestSuiteResults result = reader.parse(resultFile);

        assertEquals(TestSuiteResults.ToolType.SAST, result.getToolType());
        assertTrue(result.isCommercial());
        assertEquals("GitLab-SAST", result.getToolName());

        assertEquals(5, result.getTotalResults());

        assertEquals(CweNumber.WEAK_CRYPTO_ALGO, result.get(1).get(0).getCWE());
        assertEquals(CweNumber.PATH_TRAVERSAL, result.get(5).get(0).getCWE());
    }

    @Test
    void isAbleToFetchTestFileClassName() {
        JSONArray vulnerabilities = resultFile.json().getJSONArray("vulnerabilities");
        String path = vulnerabilities.getJSONObject(1).getJSONObject("location").getString("file");

        assertEquals("src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00614.java", path);

        String className = (path.substring(path.lastIndexOf('/') + 1)).split("\\.")[0];
        assertTrue(className.startsWith(BenchmarkScore.TESTCASENAME));

        JSONArray identifiers = vulnerabilities.getJSONObject(1).getJSONArray("identifiers");
        int cwe = identifiers.getJSONObject(1).getInt("value");
        assertEquals(327, cwe);

        String category = identifiers.getJSONObject(2).getString("name");
        category = category.split("-")[1].strip();
        assertEquals("Cryptographic Failures", category);

        String evidence = vulnerabilities.getJSONObject(1).getString("cve");
        assertEquals("semgrep_id:find_sec_bugs.CIPHER_INTEGRITY-1:71:71", evidence);
    }
}