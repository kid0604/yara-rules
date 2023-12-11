import "math"

rule WEBSHELL_JSP_ReGeorg
{
	meta:
		description = "Webshell regeorg JSP version"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		reference = "https://github.com/sensepost/reGeorg"
		hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2021/01/24"
		modified = "2023-04-05"
		score = 75
		hash = "650eaa21f4031d7da591ebb68e9fc5ce5c860689"
		hash = "00c86bf6ce026ccfaac955840d18391fbff5c933"
		hash = "6db49e43722080b5cd5f07e058a073ba5248b584"
		hash = "9108a33058aa9a2fb6118b719c5b1318f33f0989"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$jgeorg1 = "request" fullword wide ascii
		$jgeorg2 = "getHeader" fullword wide ascii
		$jgeorg3 = "X-CMD" fullword wide ascii
		$jgeorg4 = "X-STATUS" fullword wide ascii
		$jgeorg5 = "socket" fullword wide ascii
		$jgeorg6 = "FORWARD" fullword wide ascii
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
		filesize <300KB and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and all of ($jgeorg*)
}
