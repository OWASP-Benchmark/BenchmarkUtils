package org.owasp.benchmarkutils.score.report.html;

public class HtmlStringBuilder {

    private final StringBuilder sb = new StringBuilder();

    //    public void append(String rawString) {
    //        sb.append(rawString);
    //    }

    public HtmlStringBuilder beginTable() {
        sb.append("<table>");

        return this;
    }

    public HtmlStringBuilder beginTable(String cssClass) {
        if (cssClass == null) {
            return beginTable();
        }

        sb.append("<table class=\"").append(cssClass).append("\">");

        return this;
    }

    public HtmlStringBuilder beginTr() {
        sb.append("<tr>");

        return this;
    }

    public HtmlStringBuilder beginTr(String cssClass) {
        if (cssClass == null) {
            return beginTr();
        }

        sb.append("<tr class=\"").append(cssClass).append("\">");

        return this;
    }

    public HtmlStringBuilder th(String content) {
        sb.append("<th>").append(content).append("</th>");

        return this;
    }

    public HtmlStringBuilder th(String content, String cssClass) {
        if (cssClass == null) {
            return th(content);
        }

        sb.append("<th class=\"").append(cssClass).append("\">").append(content).append("</th>");

        return this;
    }

    public HtmlStringBuilder endTr() {
        sb.append("</tr>");

        return this;
    }

    public HtmlStringBuilder td(String content) {
        sb.append("<td>").append(content).append("</td>");

        return this;
    }

    public HtmlStringBuilder td(String content, String cssClass) {
        if (cssClass == null) {
            return td(content);
        }

        sb.append("<td class=\"").append(cssClass).append("\">").append(content).append("</td>");

        return this;
    }

    public HtmlStringBuilder endTable() {
        sb.append("</table>");

        return this;
    }

    @Override
    public String toString() {
        return sb.toString();
    }

    public HtmlStringBuilder p(String content) {
        sb.append("<p>").append(content).append("</p>");

        return this;
    }
}
