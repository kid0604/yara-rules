import "pe"

rule SEAAXE_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { FC BC [2] 0E 1F E8 [2] 26 A1 [2] 8B 1E [2] 2B C3 8E C0 B1 ?? D3 E3 }

	condition:
		$a0 at pe.entry_point
}
