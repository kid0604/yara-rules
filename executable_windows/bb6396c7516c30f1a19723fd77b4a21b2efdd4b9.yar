import "pe"

rule tElockv04xv05x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of tElockv04xv05x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C1 EE 00 66 8B C9 EB 01 EB 60 EB 01 EB 9C E8 00 00 00 00 5E 83 C6 ?? 8B FE 68 79 01 [2] 59 EB 01 }

	condition:
		$a0 at pe.entry_point
}
