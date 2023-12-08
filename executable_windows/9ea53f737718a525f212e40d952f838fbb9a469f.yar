import "pe"

rule Armadillov430v440SiliconRealmsToolworks
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v4.30 - v4.40 Silicon Realms Toolworks"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 40 [2] 00 68 80 [2] 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 88 [2] 00 33 D2 8A D4 89 15 30 [2] 00 8B C8 81 E1 FF 00 00 00 89 0D 2C [2] 00 C1 E1 08 03 CA 89 0D 28 [2] 00 C1 E8 10 A3 24 }
		$a1 = { 60 E8 00 00 00 00 5D 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 FD EB 0B F2 EB F5 EB F6 F2 EB 08 FD EB E9 F3 EB E4 FC E9 9D 0F C9 8B CA F7 D1 59 58 50 51 0F CA F7 D2 9C F7 D2 0F CA EB 0F B9 EB 0F B8 EB 07 B9 EB 0F 90 EB 08 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
