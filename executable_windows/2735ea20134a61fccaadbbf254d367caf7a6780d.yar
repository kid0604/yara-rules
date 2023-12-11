import "pe"

rule NativeUDPacker11ModdedPoisonIvyShellcodeokkixot
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NativeUDPacker11ModdedPoisonIvyShellcodeokkixot in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 31 C0 31 DB 31 C9 EB 0E 6A 00 6A 00 6A 00 6A 00 FF 15 28 41 40 00 FF 15 94 40 40 00 89 C7 68 88 13 00 00 FF 15 98 40 40 00 FF 15 94 40 40 00 81 C7 88 13 00 00 39 F8 73 05 E9 84 00 00 00 6A 40 68 00 10 00 00 FF 35 04 30 40 00 6A 00 FF 15 A4 40 40 00 89 C7 FF 35 04 30 40 00 68 CA 10 40 00 50 FF 15 A8 40 40 00 6A 40 68 00 10 00 00 FF 35 08 30 40 00 6A 00 FF 15 A4 40 40 00 89 C6 68 00 30 40 00 FF 35 04 30 40 00 57 FF 35 08 30 40 00 50 6A 02 FF 15 4E 41 40 00 6A 00 6A 00 6A 00 56 6A 00 6A 00 FF 15 9C 40 40 00 50 6A 00 6A 00 6A 11 50 FF 15 4A 41 40 00 58 6A FF 50 FF 15 AC 40 40 00 6A 00 FF 15 A0 40 }

	condition:
		$a0 at pe.entry_point
}
