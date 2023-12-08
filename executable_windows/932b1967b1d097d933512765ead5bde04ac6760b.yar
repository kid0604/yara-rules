import "pe"

rule InnoSetupModulev109a
{
	meta:
		author = "malware-lu"
		description = "Detects Inno Setup installer module version 1.09a"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 C0 53 56 57 33 C0 89 45 F0 89 45 C4 89 45 C0 E8 A7 7F FF FF E8 FA 92 FF FF E8 F1 B3 FF FF 33 C0 }

	condition:
		$a0 at pe.entry_point
}
