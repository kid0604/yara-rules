import "pe"

rule InnoSetupModulev304betav306v307
{
	meta:
		author = "malware-lu"
		description = "Detects Inno Setup module versions 3.04 beta, 3.06, and 3.07"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 B3 70 FF FF E8 1A 85 FF FF E8 25 A7 FF FF E8 6C }

	condition:
		$a0
}
