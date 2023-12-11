import "pe"

rule MSLRHV031emadicius
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 D1 CB 0F CA C1 CA E0 D1 CA 0F C8 EB 01 F1 }

	condition:
		$a0 at pe.entry_point
}
