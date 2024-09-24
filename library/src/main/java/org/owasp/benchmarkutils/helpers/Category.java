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
 * @author David Anderson
 * @created 2021
 */
package org.owasp.benchmarkutils.helpers;

import java.util.HashSet;
import java.util.Set;

/*
 * This class contains a single vulnerability category. And is Comparable to other Category instances
 * via its 'name' attribute (i.e., the long name).
 */
public class Category implements Comparable<Category> {

    private final String id; // e.g., pathtraver
    private final String name; // e.g., Path Traversal
    private final int CWE;
    private final boolean isInjection;
    private final String shortName; // The shortname from categories.xml, e.g., PATHT, XSS, AUTH
    private final Set<Integer> childOf;
    private final Set<Integer> parentOf;

    /**
     * Create a vuln category.
     *
     * @param id The short name for the category, e.g., pathtraver
     * @param name The long name of the category, e.g., Path Traversal
     * @param cwe The associated CWE number.
     * @param isInjection Whether this vuln category is a type of injection attack.
     * @param shortname The shortname for the category. Used where keeping length to a minimum is
     *     helpful, e.g., PATHT
     * @param childOf CWEs that are children of this CWE (per MITRE CWE db). Can be null or an empty
     *     Set if there are none.
     * @param parentOf CWEs that are parents of this CWE (per MITRE CWE db). Can be null or an empty
     *     Set if there are none.
     */
    public Category(
            String id,
            String name,
            int cwe,
            boolean isInjection,
            String shortname,
            Set<Integer> childOf,
            Set<Integer> parentOf) {
        this.id = id;
        if (name.contains("/") || name.contains("\\")) {
            System.err.println(
                    "FATAL ERROR: CWE name '"
                            + name
                            + "' from provided "
                            + Categories.FILENAME
                            + " file: contains a path character, which breaks scorecard generation.");
            System.exit(-1);
        }
        this.name = name;
        this.CWE = cwe;
        this.isInjection = isInjection;
        this.shortName = shortname.toUpperCase();
        this.childOf = (childOf == null ? new HashSet<Integer>() : childOf);
        this.parentOf = (parentOf == null ? new HashSet<Integer>() : parentOf);
    }

    public String getId() {
        return this.id;
    }

    /**
     * The string id for this CWE from categories.xml, e.g., pathtraver, xpathi, xss
     *
     * @return The name
     */
    public String getName() {
        return this.name;
    }

    public int getCWE() {
        return this.CWE;
    }

    public boolean isInjection() {
        return this.isInjection;
    }

    /**
     * Determines if the supplied CWE is a child of this CWE category.
     *
     * @param cwe Potential child CWE number.
     * @return True if supplied CWE is a child CWE of this CWE category, false otherwise.
     */
    public boolean isChildOf(int cwe) {
        return this.childOf.contains(Integer.valueOf(cwe));
    }

    /**
     * Determines if the supplied CWE is a parent of this CWE category.
     *
     * @param cwe Potential parent CWE number.
     * @return True if supplied CWE is a parent CWE of this CWE category, false otherwise.
     */
    public boolean isParentOf(int cwe) {
        return this.parentOf.contains(Integer.valueOf(cwe));
    }

    /**
     * The shortname for this CWE from categories.xml, e.g., PATH, XSS, AUTH
     *
     * @return The short name
     */
    public String getShortName() {
        return this.shortName;
    }

    public String toString() {
        return getId();
    }

    @Override
    public int compareTo(Category cat) {
        if (this.id.equals(cat)) return 0;
        return this.name.compareTo(cat.name);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this) return true;
        if (!(o instanceof Category)) return false;
        Category other = (Category) o;
        return (this.id == null && other.id == null)
                || (this.id != null && this.id.equals(other.id));
    }
}
