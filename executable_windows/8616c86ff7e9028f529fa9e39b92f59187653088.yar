import "pe"

rule Thinstallv2460Jitit
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall v2.460 JITIT malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 51 53 56 57 6A 00 6A 00 FF 15 F4 18 40 00 50 E8 87 FC FF FF 59 59 A1 94 1A 40 00 8B 40 10 03 05 90 1A 40 00 89 45 FC 8B 45 FC FF E0 5F 5E 5B C9 C3 00 00 00 76 0C 00 00 D4 0C 00 00 1E }

	condition:
		$a0 at pe.entry_point
}
