import "math"

rule WEBSHELL_JSP_HTTP_Proxy
{
	meta:
		description = "Webshell JSP HTTP proxy"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash = "2f9b647660923c5262636a5344e2665512a947a4"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2023-07-05"
		hash = "97c1e2bf7e769d3fc94ae2fc74ac895f669102c6"
		hash = "2f9b647660923c5262636a5344e2665512a947a4"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$jh1 = "OutputStream" fullword wide ascii
		$jh2 = "InputStream" wide ascii
		$jh3 = "BufferedReader" fullword wide ascii
		$jh4 = "HttpRequest" fullword wide ascii
		$jh5 = "openConnection" fullword wide ascii
		$jh6 = "getParameter" fullword wide ascii
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide

	condition:
		filesize <10KB and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and all of ($jh*)
}
