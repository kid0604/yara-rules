import "math"

rule WEBSHELL_JSP_Generic_Reflection
{
	meta:
		description = "Generic JSP webshell which uses reflection to execute user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "62e6c6065b5ca45819c1fc049518c81d7d165744"
		hash = "bf0ff88cbb72c719a291c722ae3115b91748d5c4920afe7a00a0d921d562e188"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ws_exec = "invoke" fullword wide ascii
		$ws_class = "Class" fullword wide ascii
		$fp = "SOAPConnection"
		$cjsp_short1 = "<%" ascii wide
		$cjsp_short2 = "%>" wide ascii
		$cjsp_long1 = "<jsp:" ascii wide
		$cjsp_long2 = /language=[\"']java[\"\']/ ascii wide
		$cjsp_long3 = "/jstl/core" ascii wide
		$cjsp_long4 = "<%@p" nocase ascii wide
		$cjsp_long5 = "<%@ " nocase ascii wide
		$cjsp_long6 = "<% " ascii wide
		$cjsp_long7 = "< %" ascii wide
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
		$cj_encoded1 = "\"java.util.Base64$Decoder\"" ascii wide

	condition:
		all of ($ws_*) and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and not $fp and ( filesize <10KB and ( any of ($input*) and any of ($req*)) or ( filesize <30KB and any of ($cj_encoded*) and math.entropy(500, filesize -500)>=5.5 and math.mean(500, filesize -500)>80 and math.deviation(500, filesize -500,89.0)<23))
}
