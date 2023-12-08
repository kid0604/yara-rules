import "pe"

rule APT15_Malware_Mar18_RoyalDNS
{
	meta:
		description = "Detects malware from APT 15 report by NCC Group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/HZ5XMN"
		date = "2018-03-10"
		hash1 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "del c:\\windows\\temp\\r.exe /f /q" fullword ascii
		$x2 = "%s\\r.exe" fullword ascii
		$s1 = "rights.dll" fullword ascii
		$s2 = "\"%s\">>\"%s\"\\s.txt" fullword ascii
		$s3 = "Nwsapagent" fullword ascii
		$s4 = "%s\\r.bat" fullword ascii
		$s5 = "%s\\s.txt" fullword ascii
		$s6 = "runexe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <200KB and ((pe.exports("RunInstallA") and pe.exports("RunUninstallA")) or 1 of ($x*) or 2 of them )
}
