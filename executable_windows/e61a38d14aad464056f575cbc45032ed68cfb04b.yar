import "pe"

rule EscargotV01Meat
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Escargot malware version 01"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 04 40 30 2E 31 60 68 61 }

	condition:
		$a0 at pe.entry_point
}
