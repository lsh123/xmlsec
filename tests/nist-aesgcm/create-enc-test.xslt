<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:enc="http://www.w3.org/2001/04/xmlenc#">
    <xsl:output method="xml" encoding="UTF-8" indent="yes"/>

    <!-- Identity template : copy all text nodes, elements and attributes -->   
    <xsl:template match="@*|node()">
        <xsl:copy>
            <xsl:apply-templates select="@*|node()" />
        </xsl:copy>
    </xsl:template>

    <!-- When matching CipherValue: do nothing -->
    <xsl:template match="enc:CipherValue"><enc:CipherValue/></xsl:template>

</xsl:stylesheet>
