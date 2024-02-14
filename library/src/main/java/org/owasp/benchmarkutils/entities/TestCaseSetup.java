package org.owasp.benchmarkutils.entities;

import javax.xml.bind.annotation.XmlSeeAlso;

@XmlSeeAlso({Sqlite3Config.class, FileCopyConfig.class, HttpClientConfig.class})
public abstract class TestCaseSetup {

    public abstract void setup() throws TestCaseSetupException;

    public abstract void close() throws TestCaseSetupException;
}
