import "pe"

rule ARMProtector01bySMoKE
{
	meta:
		author = "malware-lu"
		description = "Detects ARM Protector by SMoKE"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 5E 1F 40 00 EB 02 83 09 8D B5 EF 1F 40 00 EB 02 83 09 BA A3 11 00 00 EB 01 00 8D 8D 92 31 40 00 8B 09 E8 14 00 00 00 83 EB 01 00 8B FE E8 00 00 00 00 58 83 C0 07 50 C3 00 EB 04 58 40 50 C3 8A 06 46 EB 01 00 D0 C8 E8 14 00 00 00 83 EB 01 00 2A C2 E8 00 00 00 00 5B 83 C3 07 53 C3 00 EB 04 5B 43 53 C3 EB 01 00 32 C2 E8 0B 00 00 00 00 32 C1 EB 01 00 C0 C0 02 EB 09 2A C2 5B EB 01 00 43 53 C3 88 07 EB 01 00 47 4A 75 B4 }

	condition:
		$a0 at pe.entry_point
}
