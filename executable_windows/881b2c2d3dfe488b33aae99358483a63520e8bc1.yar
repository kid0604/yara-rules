import "pe"

rule EXEStealthv273
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of EXEStealth version 2.73"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 00 EB 2F 53 68 61 72 65 77 61 72 65 20 2D 20 45 78 65 53 74 65 61 6C 74 68 00 EB 16 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 00 60 90 E8 00 00 00 00 5D 81 ED F0 27 40 00 B9 15 00 00 00 83 C1 05 EB 05 EB FE 83 C7 56 EB 00 83 E9 02 }

	condition:
		$a0
}
