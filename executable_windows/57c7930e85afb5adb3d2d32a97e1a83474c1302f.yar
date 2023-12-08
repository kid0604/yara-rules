import "pe"

rule InnoSetupModulev2018
{
	meta:
		author = "malware-lu"
		description = "Detects Inno Setup module version 2018"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 C4 B8 53 56 57 33 C0 89 45 F0 89 45 BC 89 45 B8 E8 73 71 FF FF E8 DA 85 FF FF E8 81 A7 FF FF E8 C8 }

	condition:
		$a0
}
