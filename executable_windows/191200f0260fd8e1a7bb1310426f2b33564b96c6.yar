import "pe"

rule PEtitev12
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 CA [3] 03 ?? 04 ?? 05 ?? 06 ?? 07 ?? 08 }

	condition:
		$a0 at pe.entry_point
}
