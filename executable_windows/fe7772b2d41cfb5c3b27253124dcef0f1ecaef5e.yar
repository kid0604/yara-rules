import "pe"

rule SetupFactoryv6003SetupLauncher
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting SetupFactory v6.0.3 Setup Launcher"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 90 61 40 00 68 70 3B 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 14 61 40 00 33 D2 8A D4 89 15 5C 89 40 00 8B C8 81 E1 FF 00 00 00 89 0D 58 89 40 00 C1 E1 08 03 CA 89 0D 54 89 40 00 C1 E8 10 A3 50 89 }

	condition:
		$a0
}
