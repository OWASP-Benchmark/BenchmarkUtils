# OWASP Benchmark Utilities

This project provides utility functions for the OWASP Benchmark project.

OWASP Benchmark applications are test suites designed to verify the speed and accuracy of vulnerability detection tools. Each is a fully runnable open source (usually web) application that can be analyzed by any type of Application Security Testing (AST) tool, including SAST, DAST (like <a href="https://owasp.org/www-project-zap">OWASP ZAP</a>), and IAST tools. The intent is that all the vulnerabilities deliberately included in and scored by the Benchmark are actually exploitable so its a fair test for any kind of application vulnerability detection tool. The BenchmarkUtils project also includes scorecard generators for numerous open source and commercial AST tools, and the set of supported tools is growing all the time. The currently released OWASP Benchmark is written in Java, but efforts are underway to develop versions in other languages, and possibly support other types of AST tools, like SCA or RASP.

The public documentation for the Benchmark is on the OWASP site at <a href="https://owasp.org/www-project-benchmark">OWASP Benchmark</a> as well as the github repo at: <a href="https://github.com/OWASP/Benchmark">OWASP Benchmark GitHub</a>. Please refer to these sites for the details on how to build and run the Benchmark, how to scan it with various AST tools, and how to then score those tools against the Benchmark.

This project provides a Maven plugin for OWASP Benchmark that currently has the following capabilities:

1. Scorecard Generator - when invoked, it analyzes all the tool scan results in the /results folder as compared to the expected results file for the test suite, and generates a scorecard for all those tools in the /scorecard folder. Scorecard generation can  be invoked like so:

mvn org.owasp:benchmarkutils-maven-plugin:create-scorecard -DconfigFile=config/YOURCUSTOMconfig.yaml

Common Scorecard Generator Scripts:

Scripts like so are typically created, and included with each Benchmark test suite so scorecards can be generated against that test suite using the scorecard generation capabilities in BenchmarkUtils:
* createScorecards.sh - create scorecards for all the tools whose results are in the /results folder.
* createAnonScorecards.sh - create scorecards, but anonymize all the commercial tools scored

The CUSTOMconfig.yaml file primarily needs to specify the version of the expectedresults-##.csv file, but that's typically all that's needed.

2. Crawler - used to invoke every HTTP endpoint in a Benchmark test suite. Typically used to exercise the entire test suite so IAST and other code execution monitoring tools can identify vulnerabilities in the test suite. The Crawler can be invoked like so:

mvn -Djava.awt.headless=true org.owasp:benchmarkutils-maven-plugin:run-crawler -DcrawlerFile=data/TESTSUITENAME-crawler-http.xml

* runTimingCrawler.sh - used to exercise all the test cases to see if any run abnormally slow [TBD-how to invoke?]

3. Timer - A utility function is included that times how long a job takes to run. This is typically used to record how long it take an open source tool to scan a test suite. This scan time is commonly appended to the results file name so the scan time can be included in the generated scorecard for that tool.

How these plugins are invoked is TBD.

4. Verify presence of this Maven plugin.  A script has been provided in most Benchmark projects to verify this plugin has been installed, and if it hasn't, it tells you where and how to get it. You'll see the following line as the 1st line of most scripts that invoke this plugin:

source "scripts/verifyBenchmarkPluginAvailable.sh"

