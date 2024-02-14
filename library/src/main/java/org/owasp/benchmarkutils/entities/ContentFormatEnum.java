package org.owasp.benchmarkutils.entities;

import javax.xml.bind.annotation.*;

@XmlType(name = "ContentFormat")
@XmlEnum
public enum ContentFormatEnum {
    JSON,
    XML;
}
