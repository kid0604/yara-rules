import "pe"

rule MatrixDongleTDiGmbH
{
	meta:
		author = "malware-lu"
		description = "Detects MatrixDongleTDiGmbH malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 E8 B6 00 00 00 00 00 00 00 00 00 [6] E8 00 00 00 00 5B 2B D9 8B F8 8B 4C 24 2C 33 C0 2B CF F2 AA 8B 3C 24 8B 0A 2B CF 89 5C 24 20 80 37 A2 47 49 75 F9 8D 64 24 04 FF 64 24 FC 60 C7 42 08 [4] E8 C5 FF FF FF C3 C2 F7 29 4E 29 5A 29 E6 86 8A 89 63 5C A2 65 E2 A3 A2 }
		$a1 = { E8 00 00 00 00 E8 00 00 00 00 59 5A 2B CA 2B D1 E8 1A FF FF FF }

	condition:
		$a0 or $a1 at pe.entry_point
}
