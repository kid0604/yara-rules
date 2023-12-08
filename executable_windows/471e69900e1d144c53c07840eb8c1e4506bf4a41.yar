import "pe"

rule UPX20030XMarkusOberhumerLaszloMolnarJohnReiser
{
	meta:
		author = "malware-lu"
		description = "Detects the UPX 2.00 - 3.0 packer used by Markus Oberhumer, Laszlo Molnar, and John Reiser"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5E 89 F7 B9 [4] 8A 07 47 2C E8 3C 01 77 F7 80 3F ?? 75 F2 8B 07 8A 5F 04 66 C1 E8 08 C1 C0 10 86 C4 29 F8 80 EB E8 01 F0 89 07 83 C7 05 88 D8 E2 D9 8D [5] 8B 07 09 C0 74 3C 8B 5F 04 8D [6] 01 F3 50 83 C7 08 FF [5] 95 8A 07 47 08 C0 74 DC 89 F9 57 48 F2 AE 55 FF [5] 09 C0 74 07 89 03 83 C3 04 EB E1 FF [5] 8B AE [4] 8D BE 00 F0 FF FF BB 00 10 00 00 50 54 6A 04 53 57 FF D5 8D 87 [4] 80 20 7F 80 60 28 7F 58 50 54 50 53 57 FF D5 58 61 8D 44 24 80 6A 00 39 C4 75 FA 83 EC 80 E9 }

	condition:
		$a0
}
