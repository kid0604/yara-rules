import "pe"

rule Upackv032betaDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the Upack v0.32 beta Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [4] 42 79 44 77 69 6E 67 40 00 00 00 50 45 00 00 4C 01 02 [20] 32 }

	condition:
		$a0 at pe.entry_point
}
