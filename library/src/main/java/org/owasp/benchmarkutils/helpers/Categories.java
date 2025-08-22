/**
 * OWASP Benchmark Project
 *
 * <p>This file is part of the Open Web Application Security Project (OWASP) Benchmark Project For
 * details, please see <a
 * href="https://owasp.org/www-project-benchmark/">https://owasp.org/www-project-benchmark/</a>.
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

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * This class contains all the vulnerability categories currently defined. It is implemented as a
 * Singleton and provides lookup to get the Category that maps to a CWE or category short or long
 * name.
 */
public class Categories {
    public static String FILENAME = "categories.xml"; // Default

    private Map<Integer, Category> cweToCategoryMap;
    private Map<String, Category> idToCategoryMap;
    private Map<String, Category> nameToCategoryMap; // name (not shortname)
    private List<Category> allCategories; // Alpha Sorted by name (not shortname)

    private static Categories _instance; // The Singleton instance of this class

    // Statically load categories definitions from the category.xml resource file to instantiate
    // Category singleton
    static {
        InputStream categoriesFileStream =
                Categories.class.getClassLoader().getResourceAsStream(Categories.FILENAME);
        if (categoriesFileStream == null) {
            System.err.println(
                    "FATAL ERROR: couldn't load categories resource file: " + Categories.FILENAME);
            System.exit(-1);
        }
        initVulnCategoriesFromXMLFile(
                categoriesFileStream, "resource file: " + Categories.FILENAME);
    }

    /**
     * Allows external callers to reinitialize Category singleton to a custom Categories XML file.
     * This allows a user to change the Vuln types supported during scorecard generation. If there
     * are any problems with the specified file, this call is Fatal and halts.
     *
     * @param vulnCategoriesFileStream the InputStream to the XML Categories file
     * @param xmlFileName The filename of the supplied InputStream (used for error messages)
     */
    public static void initVulnCategoriesFromXMLFile(
            InputStream vulnCategoriesFileStream, String xmlFileName) {

        try {
            new Categories(vulnCategoriesFileStream, true);
            Categories.FILENAME = xmlFileName;
        } catch (ParserConfigurationException | SAXException | IOException e1) {
            System.err.println(
                    "FATAL ERROR: couldn't load vuln categories from custom XML file: "
                            + xmlFileName);
            e1.printStackTrace();
            System.exit(-1);
        }
    }

    /**
     * Initialize all the categories from the InputStream connected to the target XML file. If the
     * Categories singleton is already initialized, it does not reload it.
     *
     * @param xmlFileStream - the InputStream from the categories.xml file.
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    public Categories(InputStream xmlFileStream)
            throws ParserConfigurationException, SAXException, IOException {
        this(xmlFileStream, false);
    }

    /**
     * Initialize all the categories from the InputStream connected to the target XML file.
     *
     * @param xmlFileStream - the InputStream from the categories.xml file.
     * @param reload - if true, forces a reload of the XML file
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    public Categories(InputStream xmlFileStream, boolean reload)
            throws ParserConfigurationException, SAXException, IOException {
        if (Categories._instance == null || reload) {
            load(xmlFileStream);
            Categories._instance = this;
        } else {
            System.out.println(
                    "WARNING: Categories being initialized again by something, but reload ignored.");
        }
    }

    /**
     * Load the categories from the InputStream connected to the target XML file.
     *
     * @param xmlFileStream - the InputStream from the categories.xml file.
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    private void load(InputStream xmlFileStream)
            throws ParserConfigurationException, SAXException, IOException {

        Map<Integer, Category> cweToCategoryMap = new HashMap<Integer, Category>();
        Map<String, Category> idToCategoryMap = new HashMap<String, Category>();
        Map<String, Category> nameToCategoryMap = new HashMap<String, Category>();
        Map<String, Category> shortnameToCategoryMap = new HashMap<String, Category>();
        List<Category> allCategories = new ArrayList<Category>();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // avoid attacks like XML External Entities (XXE)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        DocumentBuilder db = dbf.newDocumentBuilder();

        Document document = db.parse(xmlFileStream);
        document.getDocumentElement().normalize();

        // Get all categories
        NodeList nList = document.getElementsByTagName("category");

        int previousCWENum = -1; // Used for a special error message
        for (int nodeIndex = 0; nodeIndex < nList.getLength(); nodeIndex++) {
            Node node = nList.item(nodeIndex);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                // Get each Category's details
                Element eElement = (Element) node;
                NodeList nodeList = eElement.getElementsByTagName("id");
                if (nodeList.getLength() == 0) {
                    System.err.println(
                            "FATAL ERROR: "
                                    + Categories.FILENAME
                                    + " file is missing required 'id' element for the CWE category right after CWE: "
                                    + previousCWENum);
                    System.exit(-1);
                }
                String id = nodeList.item(0).getTextContent();

                nodeList = eElement.getElementsByTagName("name");
                if (nodeList.getLength() == 0) {
                    System.err.println(
                            "FATAL ERROR: "
                                    + Categories.FILENAME
                                    + " file is missing required 'name' element for CWE category with id: "
                                    + id);
                    System.exit(-1);
                }
                String name = nodeList.item(0).getTextContent();

                NodeList cweNodeList = eElement.getElementsByTagName("cwe");
                int cwe = -1;
                if (cweNodeList.getLength() > 0) {
                    cwe = Integer.parseInt(cweNodeList.item(0).getTextContent());
                } else {
                    System.err.println(
                            "FATAL ERROR: no CWE number provided for CWE category (id, name): ("
                                    + id
                                    + ", "
                                    + name
                                    + ") in "
                                    + Categories.FILENAME);
                    System.exit(-1);
                }

                nodeList = eElement.getElementsByTagName("isInjection");
                boolean isInjection = false; // Default value
                if (nodeList.getLength() > 0) {
                    isInjection = Boolean.parseBoolean(nodeList.item(0).getTextContent());
                }

                nodeList = eElement.getElementsByTagName("shortname");
                if (nodeList.getLength() == 0) {
                    System.err.println(
                            "FATAL ERROR: no shortname provided for CWE category (id, cwe): ("
                                    + id
                                    + ", "
                                    + cwe
                                    + ") in "
                                    + Categories.FILENAME);
                    System.exit(-1);
                }
                String shortname = nodeList.item(0).getTextContent();

                // Parse the optional childof and parent of nodes and create Sets for them.
                Set<Integer> childOf = new HashSet<Integer>();
                Set<Integer> parentOf = new HashSet<Integer>();

                NodeList childOfNodeList = eElement.getElementsByTagName("childof");
                if (childOfNodeList.getLength() > 0) {
                    String[] childOfList = childOfNodeList.item(0).getTextContent().split(",");
                    for (String childOfString : childOfList) {
                        Integer childOfInt = Integer.valueOf(childOfString);
                        if (!childOf.add(childOfInt)) {
                            System.err.println(
                                    "FATAL ERROR: file "
                                            + Categories.FILENAME
                                            + " contains duplicate childof value: "
                                            + childOfInt
                                            + " for CWE: "
                                            + cwe);
                            System.exit(-1);
                        }
                    }
                }
                NodeList parentOfNodeList = eElement.getElementsByTagName("parentof");
                if (parentOfNodeList.getLength() > 0) {
                    String[] parentOfList = parentOfNodeList.item(0).getTextContent().split(",");
                    for (String parentOfString : parentOfList) {
                        Integer parentOfInt = Integer.valueOf(parentOfString);
                        if (!parentOf.add(parentOfInt)) {
                            System.err.println(
                                    "FATAL ERROR: file "
                                            + Categories.FILENAME
                                            + " contains duplicate parentof value: "
                                            + parentOfInt
                                            + " for CWE: "
                                            + cwe);
                            System.exit(-1);
                        }
                    }
                }

                Category category =
                        new Category(id, name, cwe, isInjection, shortname, childOf, parentOf);
                int cweNum = Integer.valueOf(cwe);
                if (cweToCategoryMap.get(cweNum) == null) {
                    cweToCategoryMap.put(cweNum, category);
                } else {
                    System.err.println(
                            "FATAL ERROR: duplicate CWE number: "
                                    + cwe
                                    + " found in "
                                    + Categories.FILENAME);
                    System.exit(-1);
                }
                // Lowercase the ID, name, and shortname, and getByID() and getByName() do the same
                // to facilitate matches
                String idLower = id.toLowerCase();
                if (idToCategoryMap.get(idLower) == null) {
                    idToCategoryMap.put(idLower, category);
                } else {
                    System.err.println(
                            "FATAL ERROR: duplicate <id>: '"
                                    + id
                                    + "' found in "
                                    + Categories.FILENAME);
                    System.exit(-1);
                }
                String nameLower = name.toLowerCase();
                if (nameToCategoryMap.get(nameLower) == null) {
                    nameToCategoryMap.put(nameLower, category);
                } else {
                    System.err.println(
                            "FATAL ERROR: duplicate <name>: '"
                                    + name
                                    + "' found in "
                                    + Categories.FILENAME);
                    System.exit(-1);
                }
                // We don't retain the shortname Map, we just check to detect duplication here
                String shortnameLower = shortname.toLowerCase();
                if (shortnameToCategoryMap.get(shortnameLower) == null) {
                    shortnameToCategoryMap.put(shortnameLower, category);
                } else {
                    System.err.println(
                            "FATAL ERROR: duplicate <shortname>: '"
                                    + shortname
                                    + "' found in "
                                    + Categories.FILENAME);
                    System.exit(-1);
                }
                allCategories.add(category);
                previousCWENum = cwe;
            }
        }

        this.cweToCategoryMap = cweToCategoryMap;
        this.idToCategoryMap = idToCategoryMap;
        this.nameToCategoryMap = nameToCategoryMap;
        Collections.sort(allCategories);
        this.allCategories = allCategories;
    }

    /**
     * Look up the CWE associated with the supplied vulnerability category long name.
     *
     * @param name The category name to look up the CWE for. E.g., Command Injection.
     * @return the associated CWE.
     */
    public static int getCWEByName(String name) {
        String lowerName = name.toLowerCase(); // The Map uses lowercase names
        if (_instance == null) {
            throw new NullPointerException("ERROR: Categories singleton not initialized");
        }
        if (_instance.nameToCategoryMap.get(lowerName) == null) {
            System.err.println(
                    "ERROR: No matching Category found for name: '"
                            + name
                            + "' provided to method: getCWEByName()");
            return -1;
        }
        return _instance.nameToCategoryMap.get(lowerName).getCWE();
    }

    // NOTE: All these methods return the actual internal objects so COULD be modified by the caller
    // causing unexpected side effects.

    /* Get all the categories defined. They are returned in order by LONG name. - Unused so commented out.
    public static List<Category> getAllCategories() {
        if (_instance == null) {
            throw new NullPointerException("ERROR: Categories singleton not initialized");
        }
        return _instance.allCategories;
    } */

    public static Category getCategoryByCWE(int cwe) {
        if (_instance == null) {
            throw new NullPointerException("ERROR: Categories singleton not initialized");
        }
        return _instance.cweToCategoryMap.get(Integer.valueOf(cwe));
    }

    /**
     * Return the Category matching the String ID for this CWE.
     *
     * @param id The ID to search for (e.g., hash, sqli, pathtraver)
     * @return The matching Category or null, if not found.
     */
    public static Category getCategoryById(String id) {
        if (_instance == null) {
            throw new NullPointerException("ERROR: Categories singleton not initialized");
        }
        return _instance.idToCategoryMap.get(id.toLowerCase());
    }

    /**
     * Return the Category matching the long name for this CWE.
     *
     * @param id The name to search for (e.g., 'LDAP Injection', 'Path Traversal')
     * @return The matching Category or null, if not found.
     */
    public static Category getCategoryByLongName(String name) {
        if (_instance == null) {
            throw new NullPointerException("ERROR: Categories singleton not initialized");
        }
        return _instance.nameToCategoryMap.get(name.toLowerCase());
    }
}
