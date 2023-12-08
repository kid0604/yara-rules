import "pe"

rule Petite14c199899IanLuck
{
	meta:
		author = "malware-lu"
		description = "Detects the Petite14c199899IanLuck malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 66 9C 60 50 8B D8 03 00 68 54 BC 00 00 6A 00 FF 50 14 8B CC 8D A0 54 BC 00 00 50 8B C3 8D 90 ?? 16 00 00 68 00 00 [2] 51 50 80 04 24 08 50 80 04 24 42 50 80 04 24 61 50 80 04 24 9D 50 80 04 24 BB 83 3A 00 0F 84 D8 14 00 00 8B 44 24 18 F6 }

	condition:
		$a0 at pe.entry_point
}
