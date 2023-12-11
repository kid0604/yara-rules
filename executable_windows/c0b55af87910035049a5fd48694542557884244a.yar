import "pe"

rule Pksmart10b
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BA [2] 8C C8 8B C8 03 C2 81 [3] 51 B9 [2] 51 1E 8C D3 }

	condition:
		$a0 at pe.entry_point
}
