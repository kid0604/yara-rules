import "pe"

rule ElicenseSystemV4000ViaTechInc
{
	meta:
		author = "malware-lu"
		description = "Detects Elicense System V4000 by ViaTech Inc"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 63 79 62 00 65 6C 69 63 65 6E 34 30 2E 64 6C 6C 00 00 00 00 }

	condition:
		$a0
}
