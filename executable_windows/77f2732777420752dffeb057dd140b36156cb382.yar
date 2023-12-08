import "pe"

rule SPECb2
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 57 51 53 E8 [4] 5D 8B C5 81 ED [4] 2B 85 [4] 83 E8 09 89 85 [4] 0F B6 }

	condition:
		$a0 at pe.entry_point
}
