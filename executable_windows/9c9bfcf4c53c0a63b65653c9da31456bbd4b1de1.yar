import "pe"

rule tElock096tE
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElock096tE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 59 E4 FF FF 00 00 00 00 00 00 00 [4] EE [2] 00 00 00 00 00 00 00 00 00 0E [2] 00 FE [2] 00 F6 [2] 00 00 00 00 00 00 00 00 00 1B [2] 00 06 [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 26 [2] 00 00 00 00 00 39 [2] 00 00 00 00 00 26 [2] 00 00 00 00 00 39 [2] 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C }

	condition:
		$a0 at pe.entry_point
}
