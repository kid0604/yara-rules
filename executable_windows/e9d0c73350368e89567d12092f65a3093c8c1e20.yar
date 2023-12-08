import "pe"

rule PEZipv10byBaGIE
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of the PEZipv1.0 malware by BaGIE"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { D9 D0 F8 74 02 23 DB F5 F5 50 51 52 53 8D 44 24 10 50 55 56 57 D9 D0 22 C9 C1 F7 A0 55 66 C1 C8 B0 5D 81 E6 FF FF FF FF F8 77 07 52 76 03 72 01 90 5A C1 E0 60 90 BD 1F 01 00 00 87 E8 E2 07 E3 05 17 5D 47 E4 42 41 7F 06 50 66 83 EE 00 58 25 FF FF FF FF 51 }

	condition:
		$a0
}
