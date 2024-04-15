package org.owasp.benchmarkutils.tools;

import javax.xml.bind.annotation.XmlRootElement;

@XmlRootElement
class VerifyFixOutput {
    private boolean wasExploited;
    private boolean wasBroken;

    public boolean isWasExploited() {
        return wasExploited;
    }

    public void setWasExploited(boolean wasExploited) {
        this.wasExploited = wasExploited;
    }

    public boolean isWasBroken() {
        return wasBroken;
    }

    public void setWasBroken(boolean wasBroken) {
        this.wasBroken = wasBroken;
    }
}
