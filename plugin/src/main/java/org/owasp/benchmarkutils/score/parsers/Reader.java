package org.owasp.benchmarkutils.score.parsers;

import java.util.ArrayList;
import java.util.List;
import org.owasp.benchmarkutils.score.ResultFile;
import org.owasp.benchmarkutils.score.TestSuiteResults;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public abstract class Reader {

    public boolean canRead(ResultFile resultFile) {
        return false;
    }

    public TestSuiteResults parse(ResultFile resultFile) throws Exception {
        return null;
    }

    public static Node getNamedNode(String name, NodeList list) {
        for (int i = 0; i < list.getLength(); i++) {
            Node n = list.item(i);
            if (n.getNodeName().equals(name)) {
                return n;
            }
        }
        return null;
    }
    // Returns the node inside this nodelist whose name matches 'name', that also has an attribute
    // called 'key' whose value matches 'keyvalue'

    public static Node getNamedNode(String name, String keyValue, NodeList list) {
        if ((name == null) || (keyValue == null) || (list == null)) return null;
        for (int i = 0; i < list.getLength(); i++) {
            Node n = list.item(i);
            if (n.getNodeName().equals(name)) {
                if (keyValue.equals(getAttributeValue("key", n))) {
                    return n;
                }
            }
        }
        return null;
    }

    public static Node getNamedChild(String name, Node parent) {
        NodeList children = parent.getChildNodes();
        return getNamedNode(name, children);
    }

    public static List<Node> getNamedChildren(String name, List<Node> list) {
        List<Node> results = new ArrayList<Node>();
        for (Node n : list) {
            NodeList children = n.getChildNodes();
            for (int i = 0; i < children.getLength(); i++) {
                Node child = children.item(i);
                if (child.getNodeName().equals(name)) {
                    results.add(child);
                }
            }
        }
        return results;
    }

    public static List<Node> getNamedChildren(String name, Node parent) {
        NodeList children = parent.getChildNodes();
        return getNamedNodes(name, children);
    }

    public static List<Node> getNamedNodes(String name, NodeList list) {
        List<Node> results = new ArrayList<Node>();
        for (int i = 0; i < list.getLength(); i++) {
            Node n = list.item(i);
            if (n.getNodeName().equals(name)) {
                // System.out.println(">> " + n.getNodeName() + "::" + n.getNodeValue());
                results.add(n);
            }
        }
        return results;
    }

    public static String getAttributeValue(String name, Node node) {
        if (node == null) return null;
        NamedNodeMap nnm = node.getAttributes();
        if (nnm != null) {
            Node attrnode = nnm.getNamedItem(name);
            if (attrnode != null) {
                return attrnode.getNodeValue();
            }
        }
        return null;
    }
}
