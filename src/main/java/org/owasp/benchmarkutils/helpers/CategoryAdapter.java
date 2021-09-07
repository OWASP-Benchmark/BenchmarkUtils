package org.owasp.benchmarkutils.helpers;

import javax.xml.bind.annotation.adapters.XmlAdapter;

public class CategoryAdapter extends XmlAdapter<String, Category> {

    public String marshal(Category category) {
        return category.getId();
    }

    public Category unmarshal(String value) {
        return Categories.getInstance().getById(value);
    }
}
