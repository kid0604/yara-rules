import "pe"

rule FreeCryptor02build002GlOFF
{
	meta:
		author = "malware-lu"
		description = "Detects FreeCryptor02build002GlOFF malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 33 D2 90 1E 68 1B [3] 0F A0 1F 8B 02 90 50 54 8F 02 90 90 8E 64 24 08 FF E2 58 50 33 D2 52 83 F8 01 9B 40 8A 10 89 14 24 90 D9 04 24 90 D9 FA D9 5C 24 FC 8B 5C 24 FC 81 F3 C2 FC 1D 1C 75 E3 74 01 62 FF D0 90 5A 33 C0 8B 54 24 08 90 64 8F 00 90 83 C2 08 52 5C 5A }

	condition:
		$a0
}
