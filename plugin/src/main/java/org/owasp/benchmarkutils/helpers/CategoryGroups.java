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
 * @author Dave Wichers
 * @created 2024
 */
package org.owasp.benchmarkutils.helpers;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
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
 * This class manages any Category Groups of related vulnerabilities. This is used to score results
 * of these groups, in addition to the scores for individual vuln types.
 */
public class CategoryGroups {
    private static boolean categoryMappingsEnabled =
            false; // By default, this feature isn't enabled
    private static String CONFIG_FILENAME;

    // Map of all CWEs mapped to their CategoryGroup
    private static Map<Integer, CategoryGroup> cweToCategoryGroupMap = null;
    // The name to Category map contains both longname and abbr entries
    private static Map<String, CategoryGroup> nameToCategoryGroupMap = null;
    private static List<CategoryGroup> allCategoryGroups;

    private static CategoryGroups _instance; // The Singleton instance of this class

    /**
     * Supports custom definition of CWE Groups, so scorecard results can be computed for a Group of
     * Vuln types, rather than just individual CWEs. If there are any problems with the specified
     * file, this call is Fatal and halts.
     *
     * @param xmlFileName The filename of the XML configuration file
     */
    public static void defineCategoryGroupsFromXMLFile(String xmlFileName) {
        try {
            _instance = new CategoryGroups(xmlFileName);
        } catch (ParserConfigurationException | SAXException | IOException e1) {
            System.err.println(
                    "FATAL ERROR: couldn't load category groups from XML config file: "
                            + xmlFileName);
            e1.printStackTrace();
            System.exit(-1);
        }
    }

    /**
     * Initialize all the category groups from the target XML file.
     *
     * @param xmlFileName - the name of the custom Category Mappings file.
     * @throws ParserConfigurationException
     * @throws SAXException
     * @throws IOException
     */
    CategoryGroups(String xmlFileName)
            throws ParserConfigurationException, SAXException, IOException {

        Map<Integer, CategoryGroup> cweToCategoryGroupMap = new HashMap<Integer, CategoryGroup>();
        Map<String, CategoryGroup> nameToCategoryGroupMap = new HashMap<String, CategoryGroup>();
        List<CategoryGroup> allCategoryGroups = new ArrayList<CategoryGroup>();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // avoid attacks like XML External Entities (XXE)
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        try {
            InputStream mappingCWEsFileStream = new FileInputStream(xmlFileName);

            Document document = db.parse(mappingCWEsFileStream);
            document.getDocumentElement().normalize();

            // Get all the CWE Groups
            NodeList nList = document.getElementsByTagName("cwe_group");

            for (int temp = 0; temp < nList.getLength(); temp++) {
                Node node = nList.item(temp);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    // Get each CWE group's details
                    Element eElement = (Element) node;
                    String name = eElement.getElementsByTagName("name").item(0).getTextContent();
                    String abbr = eElement.getElementsByTagName("abbr").item(0).getTextContent();
                    CategoryGroup thisCategoryGroup = new CategoryGroup(name, abbr);
                    nameToCategoryGroupMap.put(name, thisCategoryGroup);
                    nameToCategoryGroupMap.put(abbr, thisCategoryGroup);
                    // Get all the CWE nodes
                    NodeList cweNodeList = eElement.getElementsByTagName("cwe");
                    for (int t = 0; t < cweNodeList.getLength(); t++) {
                        Node cweNode = cweNodeList.item(t);
                        if (cweNode.getNodeType() == Node.ELEMENT_NODE) {
                            Element cweElement = (Element) cweNode;
                            // Process the CWE's details
                            String description = cweElement.getTextContent();
                            String cweAttribute = cweElement.getAttribute("num");
                            int cweNum = -1;
                            if (cweAttribute.length() > 0) {
                                cweNum = Integer.parseInt(cweAttribute);
                            } else {
                                System.err.println(
                                        "FATAL ERROR: no CWE num attribute provided for CWE: '"
                                                + description
                                                + "' in group: '"
                                                + abbr
                                                + "' in file: "
                                                + xmlFileName);
                                System.exit(-1);
                            }
                            CWE cwe = new CWE(cweNum, description);
                            thisCategoryGroup.addCWE(cwe);
                            CategoryGroup isThisDuplicate = cweToCategoryGroupMap.get(cweNum);
                            if (isThisDuplicate == null) {
                                // Not in any other group so add to set of mappings of each CWE to
                                // the CategoryGroup it is in
                                cweToCategoryGroupMap.put(cweNum, thisCategoryGroup);
                            } else {
                                System.err.println(
                                        "FATAL ERROR: duplicate CWE number: "
                                                + cweNum
                                                + " in group: '"
                                                + abbr
                                                + "' found in other CWE Group: '"
                                                + isThisDuplicate.getAbbrev()
                                                + "' in file: "
                                                + xmlFileName);
                                System.exit(-1);
                            }
                        } // end if (cweNode.getNodeType() == Node.ELEMENT_NODE)
                    } // end loop going through all CWEs for a Category Group
                    allCategoryGroups.add(thisCategoryGroup);
                }
            } // end loop going through all Category Groups

            // Now that everything successfully processed set the static class variables to the
            // computed values
            CategoryGroups.cweToCategoryGroupMap = cweToCategoryGroupMap;
            CategoryGroups.nameToCategoryGroupMap = nameToCategoryGroupMap;
            CategoryGroups.allCategoryGroups = allCategoryGroups;

            CategoryGroups.CONFIG_FILENAME = xmlFileName;
            CategoryGroups.categoryMappingsEnabled = true;

            System.out.println(
                    "INFO: Vuln Category Groups loaded from custom XML file: " + xmlFileName);
        } catch (FileNotFoundException e) {
            System.err.println(
                    "FATAL ERROR: couldn't find custom Vuln Category Groups XML file: "
                            + xmlFileName);
            System.exit(-1);
        }
    }

    public static boolean isCategoryGroupsEnabled() {
        return CategoryGroups.categoryMappingsEnabled;
    }

    /**
     * Returns the CategoryGroup this CWE has been mapped to. This call is fatal if the CWE is not
     * mapped to a CategoryGroup.
     *
     * @param cwe The CWE to look for in the Category Groups.
     * @return The associated CategoryGroup
     */
    public static CategoryGroup getCategoryGroupByCWE(int cwe) {
        CategoryGroup matchingGroup = CategoryGroups.cweToCategoryGroupMap.get(cwe);
        if (matchingGroup == null) {
            System.err.println(
                    "FATAL ERROR: Expected CWE #: " + cwe + " not mapped to any CategoryGroup");
            System.exit(-1);
        }
        return matchingGroup;
    }

    /**
     * Returns the CategoryGroup this name has been mapped to. Works for both long names and
     * abbreviation names of a CategoryGroup. This call is fatal if this name isn't mapped to a
     * CategoryGroup.
     *
     * @param name The name to look for in the Category Groups.
     * @return The associated CategoryGroup
     */
    public static CategoryGroup getCategoryGroupByName(String name) {
        CategoryGroup matchingGroup = CategoryGroups.nameToCategoryGroupMap.get(name);
        if (matchingGroup == null) {
            new Exception(
                            "FATAL ERROR: Expected long name or abbr: '"
                                    + name
                                    + "' not mapped to any CategoryGroup")
                    .printStackTrace();
            System.exit(-1);
        }
        return matchingGroup;
    }
}
