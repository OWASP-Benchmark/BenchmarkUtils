package org.owasp.benchmarkutils.helpers;

import org.apache.http.NameValuePair;
import org.apache.http.message.BasicNameValuePair;

public class RequestVariable {

    private String name;
    private String value;
    private String attackName;
    private String attackValue;
    private String safeName;
    private String safeValue;
    private boolean isSafe;

    public RequestVariable(
            String name,
            String value,
            String attackName,
            String attackValue,
            String safeName,
            String safeValue) {
        super();
        this.name = name;
        this.value = value;
        this.attackName = attackName;
        this.attackValue = attackValue;
        this.safeName = safeName;
        this.safeValue = safeValue;
        if (name == null) throw new NullPointerException("name parameter cannot be null");
        if (value == null) throw new NullPointerException("value parameter cannot be null");
        isSafe = name.equals(safeName) && value.equals(safeValue);
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }

    public String getAttackName() {
        return attackName;
    }

    public void setAttackName(String attackName) {
        this.attackName = attackName;
    }

    public String getAttackValue() {
        return attackValue;
    }

    public void setAttackValue(String attackValue) {
        this.attackValue = attackValue;
    }

    public String getSafeName() {
        return safeName;
    }

    public void setSafeName(String safeName) {
        this.safeName = safeName;
    }

    public String getSafeValue() {
        return safeValue;
    }

    public void setSafeValue(String safeValue) {
        this.safeValue = safeValue;
    }

    public NameValuePair getNameValuePair() {
        return new BasicNameValuePair(name, value);
    }

    public boolean isSafe() {
        return isSafe;
    }

    public void setSafe(boolean isSafe) {
        this.isSafe = isSafe;
        if (isSafe) {
            if (getSafeName() != null) {
                setName(getSafeName());
            }
            if (getSafeValue() != null) {
                setValue(getSafeValue());
            }
        } else {
            if (getAttackName() != null) {
                setName(getAttackName());
            }
            if (getAttackValue() != null) {
                setValue(getAttackValue());
            }
        }
    }

    public String toString() {
        return String.format(
                "%s:%s (attackName: %s, attackValue: %s, safeName: %s, safeValue: %s)%n",
                getName(),
                getValue(),
                getAttackName(),
                getAttackValue(),
                getSafeName(),
                getSafeValue());
    }
}
