import "pe"

rule RJcrushv100
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 06 FC 8C C8 BA [2] 03 D0 52 BA [2] 52 BA [2] 03 C2 8B D8 05 [2] 8E DB 8E C0 33 F6 33 FF B9 }

	condition:
		$a0 at pe.entry_point
}
