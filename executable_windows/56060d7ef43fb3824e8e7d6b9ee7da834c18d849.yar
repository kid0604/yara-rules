rule malware_Pangolin8RAT
{
	meta:
		description = "Hunt GobLoaderScript"
		author = "JPCERT/CC Incident Response Group"
		hash = "F95441B1CD6399887E99DBE6AA0CEB0CA907E8175192E71F8F1A4CCA49E8FC82"
		os = "windows"
		filetype = "executable"

	strings:
		$func0 = { 57 41 56 41 57 48 83 EC 20 49 C7 C0 FF FF FF FF 4C 8B FA 49 8B D8 48 8B F9 66 90 48 FF C3 }
		$func1 = { 48 BB FE FF FF FF FF FF FF 7F 48 8B C3 4D 8B E9 49 2B C6 48 8B F1 48 3B C2 }
		$func2 = { 48 89 5D ?? 48 C7 45 ?? 07 00 00 00 66 89 5D ?? 41 B8 01 00 00 00 48 8D 15 ?? ?? 08 00 48 8D 4D ?? E8 ?? ?? ?? ?? 90 }
		$func3 = { 41 B8 08 02 00 00 E8 ?? ?? 03 00 BA 04 01 00 00 48 8D 4C 24 ?? FF 15 ?? ?? ?? 00 4C 8D 05 ?? ?? 08 00 BA 04 01 00 00 48 8D 4C 24 ?? E8 ?? EA 03 00 48 8D 4C 24 ?? FF 15 ?? ?? ?? 00 8B D0 48 8B CF FF 15 ?? ?? ?? 00 45 33 C9 48 C7 44 24 30 00 00 00 00 C7 44 24 28 80 00 00 00 48 8D 4C 24 ?? BA 00 00 00 80 C7 44 24 20 03 00 00 00 45 8D 41 01 FF 15 ?? ?? ?? 00 48 8B D8 48 85 C0 }
		$str01 = "smcache.dat" ascii wide
		$str04 = "file:///" ascii wide

	condition:
		( uint16(0)==0x5A4D) and ( filesize <2MB) and ((3 of ($func*)) or (2 of ($str*)))
}
