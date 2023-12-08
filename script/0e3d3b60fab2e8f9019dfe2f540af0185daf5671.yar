import "math"

rule WEBSHELL_JSP_Generic_ProcessBuilder
{
	meta:
		description = "Generic JSP webshell which uses processbuilder to execute user input"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-04-05"
		hash = "82198670ac2072cd5c2853d59dcd0f8dfcc28923"
		hash = "c05a520d96e4ebf9eb5c73fc0fa446ceb5caf343"
		hash = "347a55c174ee39ec912d9107e971d740f3208d53af43ea480f502d177106bbe8"
		hash = "d0ba29b646274e8cda5be1b940a38d248880d9e2bba11d994d4392c80d6b65bd"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$exec = "ProcessBuilder" fullword wide ascii
		$start = "start" fullword wide ascii
		$input1 = "getParameter" fullword ascii wide
		$input2 = "getHeaders" fullword ascii wide
		$input3 = "getInputStream" fullword ascii wide
		$input4 = "getReader" fullword ascii wide
		$req1 = "request" fullword ascii wide
		$req2 = "HttpServletRequest" fullword ascii wide
		$req3 = "getRequest" fullword ascii wide

	condition:
		filesize <2000 and ( any of ($input*) and any of ($req*)) and $exec and $start
}
