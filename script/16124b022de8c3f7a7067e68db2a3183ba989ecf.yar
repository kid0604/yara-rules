import "math"

rule WEBSHELL_JSP_By_String
{
	meta:
		description = "JSP Webshells which contain unique strings, lousy rule for low hanging fruits. Most are catched by other rules in here but maybe these catch different versions."
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/09"
		modified = "2023-04-05"
		hash = "e9060aa2caf96be49e3b6f490d08b8a996c4b084"
		hash = "4c2464503237beba54f66f4a099e7e75028707aa"
		hash = "06b42d4707e7326aff402ecbb585884863c6351a"
		hash = "dada47c052ec7fcf11d5cfb25693bc300d3df87de182a254f9b66c7c2c63bf2e"
		hash = "f9f6c696c1f90df6421cd9878a1dec51a62e91b4b4f7eac4920399cb39bc3139"
		hash = "f1d8360dc92544cce301949e23aad6eb49049bacf9b7f54c24f89f7f02d214bb"
		hash = "1d1f26b1925a9d0caca3fdd8116629bbcf69f37f751a532b7096a1e37f4f0076"
		hash = "850f998753fde301d7c688b4eca784a045130039512cf51292fcb678187c560b"
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
		$jstring17 = "Tas9er" fullword wide ascii
		$jstring18 = "uu0028\\u" wide ascii
		$jstring19 = "uu0065\\u" wide ascii
		$jstring20 = "uu0073\\u" wide ascii
		$jstring21 = /\\uuu{0,50}00/ wide ascii
		$jstring22 = /[\w\.]\\u(FFFB|FEFF|FFF9|FFFA|200C|202E|202D)[\w\.]/ wide ascii
		$jstring23 = "\"e45e329feb5d925b\"" wide ascii
		$jstring24 = "u<![CDATA[n" wide ascii
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
		not ( uint16(0)==0x5a4d or $dex at 0 or $pack at 0 or uint16(0)==0x4b50) and (( filesize <100KB and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and any of ($jstring*)) or ( filesize <500KB and (#jstring21>20 or $jstring18 or $jstring19 or $jstring20)))
}
