import "math"

rule WEBSHELL_JSP_Generic_Tiny
{
	meta:
		description = "Generic JSP webshell tiny"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "8fd343db0442136e693e745d7af1018a99b042af"
		hash = "87c3ac9b75a72187e8bc6c61f50659435dbdc4fde6ed720cebb93881ba5989d8"
		hash = "1aa6af726137bf261849c05d18d0a630d95530588832aadd5101af28acc034b5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$payload1 = "ProcessBuilder" fullword wide ascii
		$payload2 = "URLClassLoader" fullword wide ascii
		$payload_rt1 = "Runtime" fullword wide ascii
		$payload_rt2 = "getRuntime" fullword wide ascii
		$payload_rt3 = "exec" fullword wide ascii
		$jg_sus1 = "xe /c" ascii wide
		$jg_sus2 = /getParameter\("."\)/ ascii wide
		$jg_sus3 = "</pre>" ascii wide
		$jg_sus4 = "BASE64Decoder" fullword ascii wide
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
		$fixed_cmd1 = "bash -i >& /dev/" ascii wide

	condition:
		(( filesize <1000 and any of ($jg_sus*)) or filesize <250) and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and (( any of ($input*) and any of ($req*)) or ( any of ($fixed_cmd*))) and (1 of ($payload*) or all of ($payload_rt*))
}
