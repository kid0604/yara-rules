import "pe"

rule ACProtectV14Xrisco
{
	meta:
		author = "malware-lu"
		description = "Detects ACProtect v1.4X packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 01 00 00 00 7C 83 04 24 06 C3 }

	condition:
		$a0 at pe.entry_point
}
