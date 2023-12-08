import "pe"

rule Packanoid10ackanoid
{
	meta:
		author = "malware-lu"
		description = "Detects the Packanoid10ackanoid malware based on specific byte patterns at the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BF 00 ?? 40 00 BE [3] 00 E8 9D 00 00 00 B8 [3] 00 8B 30 8B 78 04 BB [3] 00 8B 43 04 91 E3 1F 51 FF D6 56 96 8B 13 8B 02 91 E3 0D 52 51 56 FF D7 5A 89 02 83 C2 04 EB EE 83 C3 08 5E EB DB B9 [2] 00 00 BE 00 [2] 00 EB 01 00 BF [3] 00 }

	condition:
		$a0 at pe.entry_point
}
