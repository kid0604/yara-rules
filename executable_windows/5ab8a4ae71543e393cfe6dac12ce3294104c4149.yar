import "pe"

rule PCGuardv303dv305d
{
	meta:
		author = "malware-lu"
		description = "Detects PCGuard versions 3.03 and 3.05"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 50 E8 [4] 5D EB 01 E3 60 E8 03 [3] D2 EB 0B 58 EB 01 48 40 EB 01 }

	condition:
		$a0 at pe.entry_point
}
