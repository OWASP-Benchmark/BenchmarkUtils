package org.owasp.benchmarkutils.helpers;

import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("SERVLET")
public class ServletTestCase extends TestCase {
    public ServletTestCase() {}
}
