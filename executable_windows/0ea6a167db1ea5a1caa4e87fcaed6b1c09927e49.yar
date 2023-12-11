import "pe"

rule GPInstallv50332
{
	meta:
		author = "malware-lu"
		description = "Detects the installation of GPInstall version 5.0.332"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 33 C9 51 51 51 51 51 51 51 53 56 57 B8 C4 1C 41 00 E8 6B 3E FF FF 33 C0 55 68 76 20 41 00 64 FF 30 64 89 20 BA A0 47 41 00 33 C0 E8 31 0A FF FF 33 D2 A1 A0 }

	condition:
		$a0
}
