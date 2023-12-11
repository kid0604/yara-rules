import "pe"

rule SiliconRealmsInstallStub
{
	meta:
		author = "malware-lu"
		description = "Detects Silicon Realms Install Stub"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 ?? 92 40 00 68 [2] 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 [2] 40 00 33 D2 8A D4 89 15 [2] 40 00 8B C8 81 E1 FF 00 00 00 89 0D [2] 40 00 C1 E1 08 03 CA 89 0D [2] 40 00 C1 E8 10 A3 }

	condition:
		$a0
}
