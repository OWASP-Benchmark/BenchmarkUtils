/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https:/owasp.org/www-project-benchmark/</a>.
 *
 * <p>The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, version 2.
 *
 * <p>The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.
 *
 * @author Dave Wichers
 * @created 2024
 */
package org.owasp.benchmarkutils.helpers;

import java.util.HashMap;
import java.util.Map;

/*
 * This class contains a single vulnerability group. Each group has a set of associated CWEs, so the entire group can be scored in the same manner that an individual vulnerability category can be scored.
 */
public class CategoryGroup implements Comparable<CategoryGroup> {

    private final String longname; // e.g., Authentication and Access Control
    private final String abbreviation; // The abbreviation for this Group of CWEs, e.g., AAC
    private Map<Integer, CWE> cweToCategoryGroupMap; // All the CWEs mapped to this Category Group

    /**
     * Create a Category Group
     *
     * @param longname The long name of this category group, e.g., Authentication and Access Control
     * @param abbreviation The abbreviation for this group, e.g., AAC
     */
    public CategoryGroup(String longname, String abbreviation) {
        this.longname = longname;
        this.abbreviation = abbreviation;
        this.cweToCategoryGroupMap = new HashMap<Integer, CWE>();
    }

    /**
     * The full name of this Category Group, e.g., Authentication and Access Control
     *
     * @return The name
     */
    public String getLongName() {
        return this.longname;
    }

    /**
     * The abbreviation for this Category Group, e.g., AAC
     *
     * @return The abbreviation
     */
    public String getAbbrev() {
        return this.abbreviation;
    }

    public void addCWE(CWE cwe) {
        if (cwe == null) throw new IllegalArgumentException("supplied CWE cannot be null");
        int cweNum = cwe.getCWENumber();
        if (this.cweToCategoryGroupMap.get(cweNum) == null) {
            this.cweToCategoryGroupMap.put(cweNum, cwe);
        } else {
            System.err.println(
                    "FATAL ERROR: duplicate CWE number: "
                            + cweNum
                            + " being added to Category Group: "
                            + this.abbreviation);
            System.exit(-1);
        }
    }

    /**
     * Gets the CWE from this Category Group if it exists.
     *
     * @param cweNum The CWE number to search for.
     * @return The matching CWE in this Category Group, or null it not in this group.
     */
    public CWE getCWE(int cweNum) {
        return this.cweToCategoryGroupMap.get(cweNum);
    }

    public String toString() {
        return this.longname + "::" + this.abbreviation;
    }

    @Override
    public int compareTo(CategoryGroup cat) {
        if (this.abbreviation.equals(cat.abbreviation)) return 0;
        return this.abbreviation.compareTo(cat.abbreviation);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof CategoryGroup)) return false;
        CategoryGroup other = (CategoryGroup) o;
        return (this.abbreviation.equals(other.abbreviation));
    }
}
