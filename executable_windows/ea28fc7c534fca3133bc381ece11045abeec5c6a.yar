import "pe"

rule ASDPack20asd
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of ASDPack20asd malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 [4] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [4] 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 8D 49 00 1F 01 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 90 }
		$a1 = { 5B 43 83 7B 74 00 0F 84 08 00 00 00 89 43 14 E9 }
		$a2 = { 8B 44 24 04 56 57 53 E8 CD 01 00 00 C3 00 00 00 00 00 00 00 00 00 00 00 00 00 10 00 00 00 }

	condition:
		$a0 or $a1 or $a2 at pe.entry_point
}
