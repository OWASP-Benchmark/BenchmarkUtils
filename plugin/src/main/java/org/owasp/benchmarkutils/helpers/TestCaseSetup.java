package org.owasp.benchmarkutils.helpers;

import javax.xml.bind.annotation.XmlSeeAlso;

@XmlSeeAlso({Sqlite3Config.class, FileCopyConfig.class, HttpClientConfig.class})
public abstract class TestCaseSetup {

    abstract void setup() throws TestCaseSetupException;
}
