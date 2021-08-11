# OWASP Benchmark Utilities

This project provides utility functions for the OWASP Benchmark project.

The public documentation for the Benchmark is on the OWASP site at <a href="https://owasp.org/www-project-benchmark">OWASP Benchmark</a> as well as the github repo at: <a href="https://github.com/OWASP/Benchmark">OWASP Benchmark GitHub</a>. Please refer to these sites for the details on how to build and run the Benchmark, how to scan it with various AST tools, and how to then score those tools against the Benchmark.

This project provides a Maven plugin for OWASP Benchmark that currently has the following capabilities:

1. Scorecard Generator - when invoked, it analyzes all the tool scan results in the /results folder as compared to the expected results file for the test suite, and generates a scorecard for all those tools in the /scorecard folder.

Scorecard generation can now be invoked like so:

mvn org.owasp:benchmarkutils-maven-plugin:create-scorecard -DconfigFile=config/YOURCUSTOMconfig.yaml

The CUSTOMconfig.yaml file primarily needs to specify the version of the expectedresults-##.csv file, but that's typically all that's needed.

2. Crawler - used to invoke every HTTP endpoint in a Benchmark test suite. Typically used to exercise the entire test suite so IAST and other code execution monitoring tools can identify vulnerabilities in the test suite

3. Timer - A utility function is included that times how long a job takes to run. This is typically used to record how long it take an open source tool to scan a test suite. This scan time is commonly appended to the results file name so the scan time can be included in the generated scorecard for that tool.

How these plugins are invoked is TBD.
