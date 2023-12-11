import "math"

rule webshell_jsp_generic_classloader
{
	meta:
		description = "Detect the risk of malicious file (jspwebshell)  Rule 52"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$exec = "extends ClassLoader" wide ascii
		$class = "defineClass" fullword wide ascii
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

	condition:
		filesize <10KB and ($cjsp_short1 at 0 or any of ($cjsp_long*) or $cjsp_short2 in ( filesize -100.. filesize ) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and ( any of ($input*) and any of ($req*)) and $exec and $class
}
