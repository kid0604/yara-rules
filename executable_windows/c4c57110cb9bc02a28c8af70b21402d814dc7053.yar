import "pe"

rule eXPressorv14CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXPressor v1.4 by CGSoftLabs"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC ?? 53 56 57 EB 0C 45 78 50 72 2D 76 2E 31 2E 34 2E 2E B8 }
		$a1 = { 65 58 50 72 2D 76 2E 31 2E 34 2E }

	condition:
		$a0 at pe.entry_point or $a1
}
