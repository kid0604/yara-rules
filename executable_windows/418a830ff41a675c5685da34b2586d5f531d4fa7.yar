import "pe"

rule CHECKPRGc1992
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 C0 BE [2] 8B D8 B9 [2] BF [2] BA [2] 47 4A 74 }

	condition:
		$a0 at pe.entry_point
}
