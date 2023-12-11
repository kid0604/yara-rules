import "pe"

rule RLPack118DllaPlib043ap0x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of RLPack118DllaPlib043ap0x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 80 7C 24 08 01 0F 85 5C 01 00 00 60 E8 00 00 00 00 8B 2C 24 83 C4 ?? 8D B5 1A 04 00 00 8D 9D C1 02 00 00 33 FF E8 61 01 00 00 EB 0F FF 74 37 04 FF 34 37 FF D3 83 C4 ?? 83 C7 ?? 83 3C 37 00 75 EB 83 BD 06 04 00 00 00 74 0E 83 BD 0A 04 00 00 00 74 05 E8 D7 01 00 00 8D 74 37 04 53 6A ?? 68 [4] 68 [4] 6A ?? FF 95 A7 03 00 00 89 85 16 04 00 00 5B FF B5 16 04 00 00 56 FF D3 83 C4 ?? 8B B5 16 04 00 00 8B C6 EB 01 }

	condition:
		$a0 at pe.entry_point
}
