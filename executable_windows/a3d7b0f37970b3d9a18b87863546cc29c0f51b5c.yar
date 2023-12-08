import "pe"

rule MALWARE_Win_Gelsenicine
{
	meta:
		author = "ditekSHen"
		description = "Detects Gelsenicine"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "System/" fullword wide
		$s2 = "Windows/" fullword wide
		$s3 = "CommonAppData/" fullword wide
		$s5 = ".?AUEmbeddedResource@@" fullword ascii
		$ms1 = "pulse" fullword wide
		$ms2 = "mainpath" fullword wide
		$ms3 = "mainpath64" fullword wide
		$ms4 = "pluginkey" fullword wide
		$o1 = { 48 8d 54 24 68 48 8b 4c 39 10 e8 4d ff ff ff 44 }
		$o2 = { 48 8d 54 24 30 48 8b cb e8 34 f2 ff ff 84 c0 74 }
		$o3 = { 48 c7 44 24 ?? fe ff ff ff 49 8b f0 48 8b d9 ?? }
		$o4 = { 89 44 24 30 89 44 24 34 48 8b 53 08 48 85 d2 48 }
		$o5 = { ff ff ff ff 49 f7 d1 4c 23 f8 8b 43 10 48 8b e9 }
		$o6 = { 83 c4 24 85 c0 74 3c 8b 0b 8b 41 34 8b 4d 34 2b }
		$o7 = { 8b 45 34 8b 53 fc 50 8b cf 6a 04 68 00 10 00 00 }
		$o8 = { 80 74 1f 8b 4e 34 8b 54 24 18 25 ff ff 00 00 51 }
		$o9 = { eb 47 8b 4c 24 14 8b 56 34 52 8d 3c 08 8b 44 24 }
		$o10 = { 8b 44 24 0c 5d 5e 5b 83 c4 10 c3 8b 4e 34 51 57 }
		$o11 = { 6a 03 53 53 56 68 34 00 e4 74 ff 15 80 d0 e3 74 }

	condition:
		uint16(0)==0x5a4d and (( all of ($s*) and (3 of ($ms*) or 4 of ($o*))) or ( all of ($ms*) and 2 of ($s*) and 3 of ($o*)))
}
