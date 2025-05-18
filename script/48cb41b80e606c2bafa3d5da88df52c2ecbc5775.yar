import "math"

rule WEBSHELL_JSP_Writer_Nano_alt_2
{
	meta:
		description = "JSP file writer"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/24"
		modified = "2024-12-09"
		hash = "ac91e5b9b9dcd373eaa9360a51aa661481ab9429"
		hash = "c718c885b5d6e29161ee8ea0acadb6e53c556513"
		hash = "9f1df0249a6a491cdd5df598d83307338daa4c43"
		hash = "5e241d9d3a045d3ade7b6ff6af6c57b149fa356e"
		id = "422a18f2-d6d4-5b42-be15-1eafe44e01cf"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$payload1 = ".write" wide ascii
		$payload2 = "getBytes" fullword wide ascii
		$payload3 = ".decodeBuffer" wide ascii
		$payload4 = "FileOutputStream" fullword wide ascii
		$logger1 = "getLogger" fullword ascii wide
		$logger2 = "FileHandler" fullword ascii wide
		$logger3 = "addHandler" fullword ascii wide
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide
		$jw_sus1 = /getParameter\("."\)/ ascii wide
		$jw_sus4 = "yoco" fullword ascii wide
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
		( any of ($input*) and any of ($req*)) and ( filesize <200 or ( filesize <1000 and any of ($jw_sus*))) and ($cjsp_short1 at 0 or any of ($cjsp_long*) or ($cjsp_short1 and $cjsp_short2 in ( filesize -100.. filesize )) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and (2 of ($payload*) or all of ($logger*))
}
