<xsl:stylesheet version = '1.0' xmlns:xsl='http://www.w3.org/1999/XSL/Transform'>
    <xsl:output method="html" encoding="ISO-8859-1" />
    <xsl:template match="/">
<html>
<head>
<xsl:copy-of select="//head/*" />
</head>
<body>
<xsl:copy-of select="//body/*" />
<script>
  (function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){
  (i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),
  m=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)
  })(window,document,'script','https://www.google-analytics.com/analytics.js','ga');

  ga('create', 'UA-51404834-1', 'auto');
  ga('send', 'pageview');
</script>
</body>
</html></xsl:template>
</xsl:stylesheet>
