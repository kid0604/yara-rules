import "pe"

rule UpackV036Dwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v0.36 Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0B 01 [14] 18 10 00 00 10 00 00 00 [8] 00 10 00 00 00 02 00 00 [12] 00 00 00 00 [32] 00 00 00 00 0A 00 00 00 00 00 00 00 00 00 00 00 [4] 14 00 00 00 [64] 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 FF 76 08 FF 76 0C BE 1C 01 }
		$a1 = { BE [4] FF 36 E9 C3 00 00 00 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
