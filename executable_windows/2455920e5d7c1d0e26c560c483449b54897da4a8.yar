import "pe"

rule InnoSetupModule_alt_1
{
	meta:
		author = "malware-lu"
		description = "Detects Inno Setup installer modules used by malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 49 6E 6E 6F 53 65 74 75 70 4C 64 72 57 69 6E 64 6F 77 00 00 53 54 41 54 49 43 }
		$a1 = { 55 8B EC 83 C4 ?? 53 56 57 33 C0 89 45 F0 89 45 ?? 89 45 ?? E8 [2] FF FF E8 [2] FF FF E8 [2] FF FF E8 [2] FF FF E8 [2] FF FF }

	condition:
		$a0 at pe.entry_point or $a1
}
