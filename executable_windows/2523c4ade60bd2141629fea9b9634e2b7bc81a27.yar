import "pe"

rule NullsoftPiMPInstallSystemv1x
{
	meta:
		author = "malware-lu"
		description = "Detects Nullsoft PiMP Install System v1.x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 83 EC 0C 53 56 57 FF 15 [2] 40 00 05 E8 03 00 00 BE [3] 00 89 44 24 10 B3 20 FF 15 28 ?? 40 00 68 00 04 00 00 FF 15 [2] 40 00 50 56 FF 15 [2] 40 00 80 3D [3] 00 22 75 08 80 C3 02 BE [3] 00 8A 06 8B 3D [2] 40 00 84 C0 74 ?? 3A C3 74 }

	condition:
		$a0
}
