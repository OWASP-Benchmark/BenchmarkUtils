package org.owasp.benchmarkutils.helpers;

import javax.xml.bind.annotation.*;

@XmlType(name = "ContentFormat")
@XmlEnum
public enum ContentFormatEnum {
    JSON,
    XML;
}
