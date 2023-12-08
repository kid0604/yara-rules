import "pe"

rule PEPACKv10byANAKiN1998
{
	meta:
		author = "malware-lu"
		description = "Detects PEPACK version 1.0 by ANAKiN1998"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 74 ?? E9 [4] 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
