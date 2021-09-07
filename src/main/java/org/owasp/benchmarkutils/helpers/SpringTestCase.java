package org.owasp.benchmarkutils.helpers;

import org.eclipse.persistence.oxm.annotations.XmlDiscriminatorValue;

@XmlDiscriminatorValue("SPRINGWS")
public class SpringTestCase extends TestCase {
    public SpringTestCase() {}
}
