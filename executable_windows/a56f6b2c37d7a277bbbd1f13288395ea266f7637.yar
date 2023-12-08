import "pe"

rule tElock098tE
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElock098tE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 [4] 1E [2] 00 00 00 00 00 00 00 00 00 3E [2] 00 2E [2] 00 26 [2] 00 00 00 00 00 00 00 00 00 4B [2] 00 36 [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 56 [2] 00 00 00 00 00 69 [2] 00 00 00 00 00 56 [2] 00 00 00 00 00 69 [2] 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 75 73 65 }

	condition:
		$a0 at pe.entry_point
}
