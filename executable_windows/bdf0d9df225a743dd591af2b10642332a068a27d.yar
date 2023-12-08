import "pe"

rule dUP2xPatcherwwwdiablo2oo2cjbnet
{
	meta:
		author = "malware-lu"
		description = "Detects dUP2xPatcher malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B CB 85 C9 74 ?? 80 3A 01 74 08 AC AE 75 0A 42 49 EB EF 47 46 42 49 EB E9 }

	condition:
		$a0
}
