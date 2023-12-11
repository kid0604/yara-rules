import "pe"

rule PEIntrov10
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B 04 24 9C 60 E8 [4] 5D 81 ED 0A 45 40 ?? 80 BD 67 44 40 [2] 0F 85 48 }

	condition:
		$a0 at pe.entry_point
}
