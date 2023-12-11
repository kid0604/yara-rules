import "pe"

rule nMacrorecorder10
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of nMacrorecorder version 1.0"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5C 6E 6D 72 5F 74 65 6D 70 2E 6E 6D 72 00 00 00 72 62 00 00 58 C7 41 00 10 F8 41 00 11 01 00 00 00 00 00 00 46 E1 00 00 46 E1 00 00 35 00 00 00 F6 88 41 00 }

	condition:
		$a0
}
