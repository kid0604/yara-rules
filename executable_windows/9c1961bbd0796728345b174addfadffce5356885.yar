import "pe"

rule WWPACKv305c4ExtractableVirusShield
{
	meta:
		author = "malware-lu"
		description = "Detects the WWPACKv305c4 extractable virus shield"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 03 05 40 1A B8 [2] 8C CA 03 D0 8C C9 81 C1 [2] 51 B9 [2] 51 06 06 B1 ?? 51 8C D3 }

	condition:
		$a0 at pe.entry_point
}
