import "pe"

rule FakeNinjav28AntiDebugSpirit
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of FakeNinjav28 Anti-Debugging Spirit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 64 A1 18 00 00 00 EB 02 C3 11 8B 40 30 EB 01 0F 0F B6 40 02 83 F8 01 74 FE EB 01 E8 90 C0 FF FF EB 03 BD F4 B5 64 A1 30 00 00 00 0F B6 40 02 74 01 BA 74 E0 50 00 64 A1 30 00 00 00 83 C0 68 8B 00 EB 00 83 F8 70 74 CF EB 02 EB FE 90 90 90 0F 31 33 C9 03 C8 0F 31 2B C1 3D FF 0F 00 00 73 EA E8 08 00 00 00 C1 3D FF 0F 00 00 74 AA EB 07 E8 8B 40 30 EB 08 EA 64 A1 18 00 00 00 EB F2 90 90 90 BA [4] FF E2 64 11 40 00 FF 35 84 11 40 00 E8 40 11 00 00 6A 00 6A 00 FF 35 70 11 40 00 FF 35 84 11 40 00 E8 25 11 00 00 FF }

	condition:
		$a0
}
