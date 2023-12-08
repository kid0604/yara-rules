import "pe"

rule PEArmorV07Xhying
{
	meta:
		author = "malware-lu"
		description = "Detects PE file with specific entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED [4] 8D B5 [4] 55 56 81 C5 [4] 55 C3 }

	condition:
		$a0 at pe.entry_point
}
