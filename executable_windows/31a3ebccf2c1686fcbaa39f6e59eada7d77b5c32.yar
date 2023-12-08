import "pe"

rule QrYPt0rbyNuTraL
{
	meta:
		author = "malware-lu"
		description = "Detects suspicious code patterns at the entry point of PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 F9 00 0F 84 8D 01 00 00 8A C3 [50] 32 C1 3C F3 75 89 [50] BA D9 04 00 00 E8 00 00 00 00 5F 81 C7 16 01 00 00 80 2C 3A 01 }
		$a1 = { 86 18 CC 64 FF 35 00 00 00 00 [50] 64 89 25 00 00 00 00 BB 00 00 F7 BF [50] B8 78 56 34 12 87 03 E8 CD FE FF FF E8 B3 }
		$a2 = { EB 00 E8 B5 00 00 00 E9 2E 01 00 00 64 FF 35 00 00 00 00 [50] 64 89 25 00 00 00 00 8B 44 24 04 }

	condition:
		$a0 or $a1 or $a2 at pe.entry_point
}
