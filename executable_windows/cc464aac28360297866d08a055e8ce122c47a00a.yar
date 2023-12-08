import "pe"

rule CreateInstallv200335
{
	meta:
		author = "malware-lu"
		description = "Detects the CreateInstallv200335 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 81 EC 0C 04 00 00 53 56 57 55 68 60 50 40 00 6A 01 6A 00 FF 15 D8 80 40 00 8B F0 FF 15 D4 80 40 00 3D B7 00 00 00 75 0F 56 FF 15 B8 80 40 00 6A 02 FF 15 A4 80 40 00 33 DB E8 F2 FE FF FF 68 02 7F 00 00 89 1D 94 74 40 00 53 89 1D 98 74 40 00 FF 15 E4 80 40 }

	condition:
		$a0
}
