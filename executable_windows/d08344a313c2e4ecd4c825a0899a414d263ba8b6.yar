import "pe"

rule SafeGuardV10Xsimonzh2000
{
	meta:
		author = "malware-lu"
		description = "Detects SafeGuardV10X malware based on specific code pattern at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 EB 29 [26] 59 9C 81 C1 E2 FF FF FF EB 01 ?? 9D FF E1 }

	condition:
		$a0 at pe.entry_point
}
