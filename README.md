# OWASP Benchmark Utilities

This project provides utility functions for the OWASP Benchmark project.

OWASP Benchmark applications are test suites designed to verify the speed and accuracy of vulnerability detection tools. Each is a fully runnable open source (usually web) application that can be analyzed by any type of Application Security Testing (AST) tool, including SAST, DAST (like <a href="https://owasp.org/www-project-zap">OWASP ZAP</a>), and IAST tools. The intent is that all the vulnerabilities deliberately included in and scored by the Benchmark are actually exploitable so its a fair test for any kind of application vulnerability detection tool. The BenchmarkUtils project includes scorecard generators for numerous open source and commercial AST tools, and the set of supported tools is growing all the time. The currently released OWASP Benchmark is written in Java, but efforts are underway to develop versions in other languages.

Public documentation for the Benchmark is on the OWASP site at <a href="https://owasp.org/www-project-benchmark">OWASP Benchmark</a> as well as the github repo at: <a href="https://github.com/OWASP-Benchmark/BenchmarkJava">OWASP Benchmark GitHub</a>. Please refer to these sites for details on how to build and run the Benchmark, how to scan it with various AST tools, and how to then score those tools against the Benchmark using the scorecard utilities provided by BenchmarkUtils.

This project provides a Maven plugin for OWASP Benchmark that currently has the following capabilities:

## Scorecard Generator  
When invoked, it analyzes all the tool scan results in the /results folder as compared to the expected results file for that test suite, and generates a scorecard for all those tools in the `/scorecard` folder. Scorecard generation can be invoked like so:

```bash
mvn org.owasp:benchmarkutils-maven-plugin:create-scorecard -DconfigFile=config/YOURCUSTOMconfig.yaml
```

### Common Scorecard Generator Scripts:

Scripts like these are typically created, and included with each Benchmark test suite so scorecards can be generated against that test suite using the scorecard generation capabilities of BenchmarkUtils:
* `createScorecards.sh` - create scorecards for all the tools whose results are in the `/results` folder.
* `createAnonScorecards.sh` - create scorecards, but anonymize all the commercial tools scored

The `CUSTOMconfig.yaml` file primarily needs to specify the version of the `expectedresults-##.csv` file. That's typically all that's needed.

## Crawler 
Used to invoke every HTTP endpoint in a Benchmark test suite. Typically used to exercise the entire test suite so IAST and other code execution monitoring tools can identify vulnerabilities in the test suite. The Crawler can be invoked like so:

```
mvn -Djava.awt.headless=true org.owasp:benchmarkutils-maven-plugin:run-crawler -DcrawlerFile=data/TESTSUITENAME-crawler-http.xml  
``` 

Note that the `TESTSUITENAME-crawler-http.xml` is generated as part of the generation of the test suite itself, so you simply need to point to the crawlerFile for that test suite.

## Verify presence of this Maven plugin.  
A script is usually provided with each test suite to verify this BenchmarkUtils maven plugin has been installed locally, and if it hasn't, it tells you where to get it and how to install it (which is really easy). You'll see the following line as the 1st line of most scripts that invoke this plugin:

```
source "scripts/verifyBenchmarkPluginAvailable.sh"
```

## Usage

All use of these utilities should be through scripts already rovided with each Benchmark style test suite. To use this, simply clone, navigate and install the plugin: 
```  
git clone https://github.com/OWASP-Benchmark/BenchmarkUtils.git 
cd BenchmarkUtils
mvn install
```  

Periodically, you should run: git pull, then: mvn install, to download any updates and build/install the latest version.

## Example
Some example invocation scripts and scoring configuration .yaml files are provided in `examplescripts_configfiles/`

