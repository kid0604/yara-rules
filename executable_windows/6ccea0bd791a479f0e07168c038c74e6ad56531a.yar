rule Codoso_Gh0st_3_alt_1
{
	meta:
		description = "Detects Codoso APT Gh0st Malware"
		author = "Florian Roth"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "bf52ca4d4077ae7e840cf6cd11fdec0bb5be890ddd5687af5cfa581c8c015fcd"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "RunMeByDLL32" fullword ascii
		$s1 = "svchost.dll" fullword wide
		$s2 = "server.dll" fullword ascii
		$s3 = "Copyright ? 2008" fullword wide
		$s4 = "testsupdate33" fullword ascii
		$s5 = "Device Protect Application" fullword wide
		$s6 = "MSVCP60.DLL" fullword ascii
		$s7 = "mail-news.eicp.net" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <195KB and $x1 or 4 of them
}
