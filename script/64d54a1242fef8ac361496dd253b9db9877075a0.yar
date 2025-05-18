import "math"

rule WEBSHELL_JSP_Generic_Classloader_alt_2
{
	meta:
		description = "Generic JSP webshell which uses classloader to execute user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		hash = "6b546e78cc7821b63192bb8e087c133e8702a377d17baaeb64b13f0dd61e2347"
		date = "2021/01/07"
		modified = "2024-12-09"
		hash = "f3a7e28e1c38fa5d37811bdda1d6b0893ab876023d3bd696747a35c04141dcf0"
		hash = "8ea2a25344e6094fa82dfc097bbec5f1675f6058f2b7560deb4390bcbce5a0e7"
		hash = "b9ea1e9f91c70160ee29151aa35f23c236d220c72709b2b75123e6fa1da5c86c"
		hash = "80211c97f5b5cd6c3ab23ae51003fd73409d273727ba502d052f6c2bd07046d6"
		hash = "8e544a5f0c242d1f7be503e045738369405d39731fcd553a38b568e0889af1f2"
		id = "037e6b24-9faf-569b-bb52-dbe671ab2e87"
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
		(($cjsp_short1 at 0 or any of ($cjsp_long*) or ($cjsp_short1 and $cjsp_short2 in ( filesize -100.. filesize )) or ($cjsp_short2 and ($cjsp_short1 in (0..1000) or $cjsp_short1 in ( filesize -1000.. filesize )))) and ( any of ($input*) and any of ($req*)) and $exec and $class) and ( filesize <10KB or ( filesize <50KB and (math.entropy(500, filesize -500)<=1 or math.entropy(500, filesize -500)>=7.7)))
}
