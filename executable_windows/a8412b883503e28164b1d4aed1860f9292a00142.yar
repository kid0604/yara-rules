import "pe"

rule EXEStealthv25
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the EXEStealth v2.5 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 90 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D E8 00 00 00 00 5D 81 ED 40 1E 40 00 B9 99 09 00 00 8D BD 88 1E 40 00 8B F7 AC }

	condition:
		$a0
}
