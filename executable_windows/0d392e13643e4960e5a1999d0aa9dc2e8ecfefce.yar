import "pe"

rule ROKRAT_Malware
{
	meta:
		description = "Detects ROKRAT Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/04/introducing-rokrat.html"
		date = "2017-04-03"
		modified = "2021-09-14"
		hash1 = "051463a14767c6477b6dacd639f30a8a5b9e126ff31532b58fc29c8364604d00"
		hash2 = "cd166565ce09ef410c5bba40bad0b49441af6cfb48772e7e4a9de3d646b4851c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "c:\\users\\appdata\\local\\svchost.exe" fullword ascii
		$x2 = "c:\\temp\\episode3.mp4" fullword ascii
		$x3 = "MAC-SIL-TED-FOO-YIM-LAN-WAN-SEC-BIL-TAB" ascii
		$x4 = "c:\\temp\\%d.tmp" ascii fullword
		$s1 = "%s%s%04d%02d%02d%02d%02d%02d.jar" fullword ascii
		$s2 = "\\Aboard\\Acm%c%c%c.exe" ascii
		$a1 = "ython" ascii fullword
		$a2 = "iddler" ascii fullword
		$a3 = "egmon" ascii fullword
		$a6 = "iresha" ascii fullword

	condition:
		uint16(0)==0x5a4d and filesize <25000KB and (1 of ($x*) or (5 of them ))
}
