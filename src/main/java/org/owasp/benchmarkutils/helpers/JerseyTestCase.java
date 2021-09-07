package org.owasp.benchmarkutils.helpers;

import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("JERSEYWS")
public class JerseyTestCase extends TestCase {
    public JerseyTestCase() {}
}
