package org.owasp.benchmarkutils.score.report.html;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class HtmlStringBuilderTest {

    @Test
    void createsTable() {
        HtmlStringBuilder sb = new HtmlStringBuilder();

        String table =
                sb.beginTable("table-class")
                        .beginTr("header")
                        .th("first th", "some-th-class")
                        .th("second th")
                        .endTr()
                        .beginTr()
                        .td("first td", "some-td-class")
                        .td("second td")
                        .endTr()
                        .endTable()
                        .beginTable()
                        .endTable()
                        .toString();

        assertEquals(
                "<table class=\"table-class\">"
                        + "<tr class=\"header\">"
                        + "<th class=\"some-th-class\">first th</th>"
                        + "<th>second th</th>"
                        + "</tr>"
                        + "<tr>"
                        + "<td class=\"some-td-class\">first td</td>"
                        + "<td>second td</td>"
                        + "</tr>"
                        + "</table>"
                        + "<table>"
                        + "</table>",
                table);
    }

    @Test
    void treatsNullCssClassAsNoneForTables() {
        HtmlStringBuilder sb = new HtmlStringBuilder();

        String table =
                sb.beginTable(null)
                        .beginTr(null)
                        .th("th", null)
                        .td("td", null)
                        .endTr()
                        .endTable()
                        .toString();

        assertEquals(
                "<table>" + "<tr>" + "<th>th</th>" + "<td>td</td>" + "</tr>" + "</table>", table);
    }

    @Test
    void createsParagraph() {
        HtmlStringBuilder sb = new HtmlStringBuilder();

        sb.p("Some paragraph");

        assertEquals("<p>Some paragraph</p>", sb.toString());
    }
}
