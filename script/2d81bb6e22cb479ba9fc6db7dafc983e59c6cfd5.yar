import "math"

rule webshell_jsp_by_string
{
	meta:
		description = "Detect the risk of malicious file (jspwebshell)  Rule 55"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$jstring1 = "<title>Boot Shell</title>" wide ascii
		$jstring2 = "String oraPWD=\"" wide ascii
		$jstring3 = "Owned by Chinese Hackers!" wide ascii
		$jstring4 = "AntSword JSP" wide ascii
		$jstring5 = "JSP Webshell</" wide ascii
		$jstring6 = "motoME722remind2012" wide ascii
		$jstring7 = "EC(getFromBase64(toStringHex(request.getParameter(\"password" wide ascii
		$jstring8 = "http://jmmm.com/web/index.jsp" wide ascii
		$jstring9 = "list.jsp = Directory & File View" wide ascii
		$jstring10 = "jdbcRowSet.setDataSourceName(request.getParameter(" wide ascii
		$jstring11 = "Mr.Un1k0d3r RingZer0 Team" wide ascii
		$jstring12 = "MiniWebCmdShell" fullword wide ascii
		$jstring13 = "pwnshell.jsp" fullword wide ascii
		$jstring14 = "session set &lt;key&gt; &lt;value&gt; [class]<br>" wide ascii
		$jstring15 = "Runtime.getRuntime().exec(request.getParameter(" nocase wide ascii
		$jstring16 = "GIF98a<%@page" wide ascii
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }

	condition:
		filesize <100KB and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and not ( uint16(0)==0x5a4d or $dex at 0 or $pack at 0 or uint16(0)==0x4b50) and any of ($jstring*)
}
