import "math"

rule webshell_jsp_generic_alt_1
{
	meta:
		description = "Detect the risk of malicious file (jspwebshell)  Rule 48"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$susp0 = "cmd" fullword nocase ascii wide
		$susp1 = "command" fullword nocase ascii wide
		$susp2 = "shell" fullword nocase ascii wide
		$susp3 = "download" fullword nocase ascii wide
		$susp4 = "upload" fullword nocase ascii wide
		$susp5 = "Execute" fullword nocase ascii wide
		$susp6 = "\"pwd\"" ascii wide
		$susp7 = "\"</pre>" ascii wide
		$fp1 = "command = \"cmd.exe /c set\";"
		$dex = { 64 65 ( 78 | 79 ) 0a 30 }
		$pack = { 50 41 43 4b 00 00 00 02 00 }
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
		$payload1 = "ProcessBuilder" fullword ascii wide
		$payload2 = "processCmd" fullword ascii wide
		$rt_payload1 = "Runtime" fullword ascii wide
		$rt_payload2 = "getRuntime" fullword ascii wide
		$rt_payload3 = "exec" fullword ascii wide

	condition:
		filesize <300KB and not ( uint16(0)==0x5a4d or $dex at 0 or $pack at 0 or uint16(0)==0x4b50) and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and ( any of ($input*) and any of ($req*)) and (1 of ($payload*) or all of ($rt_payload*)) and not any of ($fp*) and any of ($susp*)
}
