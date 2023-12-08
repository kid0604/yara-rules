import "pe"

rule ACProtectV13Xrisco
{
	meta:
		author = "malware-lu"
		description = "Detects ACProtect v1.3X Risco malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 50 E8 01 00 00 00 75 83 }

	condition:
		$a0 at pe.entry_point
}
