import "pe"

rule PROTECTEXECOMv60
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E B4 30 CD 21 3C 02 73 ?? CD 20 BE [2] E8 }

	condition:
		$a0 at pe.entry_point
}
