import "pe"

rule PCGuardv405dv410dv415d
{
	meta:
		author = "malware-lu"
		description = "Detects PCGuard versions 4.05, 4.10, and 4.15"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FC 55 50 E8 00 00 00 00 5D EB 01 }

	condition:
		$a0 at pe.entry_point
}
