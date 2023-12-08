import "pe"

rule KBySV028DLLshoooo
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] BA [4] 03 C2 FF E0 [4] 60 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
