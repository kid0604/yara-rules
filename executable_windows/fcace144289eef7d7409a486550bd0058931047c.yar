import "pe"

rule Alloy4xPGWareLLC
{
	meta:
		author = "malware-lu"
		description = "Detects Alloy4xPGWareLLC malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 02 00 00 00 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 30 40 00 87 DD 6A 04 68 00 10 00 00 68 00 02 00 00 6A 00 FF 95 A8 33 40 00 0B C0 0F 84 F6 01 00 00 89 85 2E 33 40 00 83 BD E8 32 40 00 01 74 0D 83 BD E4 32 40 00 01 74 2A 8B F8 EB 3E 68 }

	condition:
		$a0 at pe.entry_point
}
