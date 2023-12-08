import "pe"

rule muckisprotectorIImucki
{
	meta:
		author = "malware-lu"
		description = "Detects the MuckisProtector II malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 24 00 00 00 8B 4C 24 0C C7 01 17 00 01 00 C7 81 B8 00 00 00 00 00 00 00 31 C0 89 41 14 89 41 18 80 6A 00 E8 85 C0 74 12 64 8B 3D 18 00 00 00 8B 7F 30 0F B6 47 02 85 C0 74 01 C3 C7 04 24 [4] BE [4] B9 [4] 8A 06 F6 D0 88 06 46 E2 F7 C3 }

	condition:
		$a0 at pe.entry_point
}
