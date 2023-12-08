import "pe"

rule Upackv036betaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.36 beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE E0 11 [2] FF 36 E9 C3 00 00 00 48 01 [2] 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C }
		$a1 = { BE E0 11 [2] FF 36 E9 C3 00 00 00 48 01 [2] 0B 01 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C [162] 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 [54] 82 8E FE FF FF 58 8B 4E 40 5F E3 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
