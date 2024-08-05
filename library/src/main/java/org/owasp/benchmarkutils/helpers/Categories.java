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
import java.util.List;
import java.util.Map;
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
    public static final String FILENAME = "categories.xml";

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
            System.out.println(
                    "FATAL ERROR: couldn't load categories resource file: " + Categories.FILENAME);
            System.exit(-1);
        }
        initCategoriesFromXMLFile(categoriesFileStream, "resource file: " + Categories.FILENAME);
    }

    /**
     * Allows external callers to reinitialize Category singleton to a custom Categories XML file.
     * If there are any problems with the specified file, this call is Fatal and halts.
     *
     * @param categoriesFileStream the InputStream to the XML Categories file
     * @param xmlFileName The filename of the supplied InputStream (used for error messages)
     */
    public static void initCategoriesFromXMLFile(
            InputStream categoriesFileStream, String xmlFileName) {

        try {
            new Categories(categoriesFileStream, true);
        } catch (ParserConfigurationException | SAXException | IOException e1) {
            System.out.println(
                    "FATAL ERROR: couldn't load categories from categories config XML file: "
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
        if (_instance == null || reload) {
            load(xmlFileStream);
            _instance = this;
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
        List<Category> allCategories = new ArrayList<Category>();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

        // avoid attacks like XML External Entities (XXE)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

        DocumentBuilder db = dbf.newDocumentBuilder();

        Document document = db.parse(xmlFileStream);
        document.getDocumentElement().normalize();

        // Get all categories
        NodeList nList = document.getElementsByTagName("category");

        for (int temp = 0; temp < nList.getLength(); temp++) {
            Node node = nList.item(temp);
            if (node.getNodeType() == Node.ELEMENT_NODE) {
                // Print each ecategory's detail
                Element eElement = (Element) node;
                String id = eElement.getElementsByTagName("id").item(0).getTextContent();
                String name = eElement.getElementsByTagName("name").item(0).getTextContent();
                NodeList cweNodeList = eElement.getElementsByTagName("cwe");
                // Default value -- CWEs included in expected results file. Might be used during
                // scoring.
                NodeList isInjectionNodeList = eElement.getElementsByTagName("isInjection");
                boolean isInjection = false; // Default value
                if (isInjectionNodeList.getLength() > 0) {
                    isInjection =
                            Boolean.parseBoolean(isInjectionNodeList.item(0).getTextContent());
                }
                String shortname =
                        eElement.getElementsByTagName("shortname").item(0).getTextContent();
                int cwe = -1;
                if (cweNodeList.getLength() > 0) {
                    cwe = Integer.parseInt(cweNodeList.item(0).getTextContent());
                } else {
                    throw new IOException(
                            "FATAL ERROR: no CWE number provided for CWE category (id, name): ("
                                    + id
                                    + ", "
                                    + name
                                    + ") in categories.xml.");
                }
                Category category = new Category(id, name, cwe, isInjection, shortname);
                int cweNum = Integer.valueOf(cwe);
                if (cweToCategoryMap.get(cweNum) == null) {
                    cweToCategoryMap.put(cweNum, category);
                } else {
                    throw new IOException(
                            "FATAL ERROR: duplicate CWE number: "
                                    + cwe
                                    + " found in categories.xml.");
                }
                // Lowercase both the ID and name, and getByID() and getByName() do the same to
                // facilitate matches
                String idLower = id.toLowerCase();
                if (idToCategoryMap.get(idLower) == null) {
                    idToCategoryMap.put(idLower, category);
                } else {
                    throw new IOException(
                            "FATAL ERROR: duplicate <id>: '"
                                    + idLower
                                    + "' found in categories.xml.");
                }
                String nameLower = name.toLowerCase();
                if (nameToCategoryMap.get(nameLower) == null) {
                    nameToCategoryMap.put(nameLower, category);
                } else {
                    throw new IOException(
                            "FATAL ERROR: duplicate <name>: '"
                                    + nameLower
                                    + "' found in categories.xml.");
                }
                allCategories.add(category);
            }
        }

        this.cweToCategoryMap = cweToCategoryMap;
        this.idToCategoryMap = idToCategoryMap;
        this.nameToCategoryMap = nameToCategoryMap;
        Collections.sort(allCategories);
        this.allCategories = allCategories;
    }

    // NOTE: All these methods return the actual internal objects so COULD be modified by the caller
    // causing unexpected side affects.

    /** Get all the categories defined. They are returned in order by LONG name. */
    public static List<Category> getAllCategories() {
        if (_instance == null) {
            throw new NullPointerException("ERROR: Categories singleton not initialized");
        }
        return _instance.allCategories;
    }

    public static Category getByCWE(int cwe) {
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
    public static Category getById(String id) {
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
    public static Category getByName(String name) {
        if (_instance == null) {
            throw new NullPointerException("ERROR: Categories singleton not initialized");
        }
        return _instance.nameToCategoryMap.get(name.toLowerCase());
    }
}
