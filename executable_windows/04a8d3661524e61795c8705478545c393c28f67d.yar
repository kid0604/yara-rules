import "pe"

rule NsPack34NorthStar
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of NsPack34NorthStar malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 [2] FF FF 80 38 01 0F 84 42 02 00 00 C6 00 01 8B D5 2B 95 [2] FF FF 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 6A 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 68 03 00 00 03 D9 50 53 E8 B1 02 00 00 61 8B 36 8B FD 03 BD [2] FF FF 8B DF 83 3F 00 75 0A 83 C7 04 B9 00 00 00 00 EB 16 B9 01 00 00 00 03 3B 83 C3 04 83 3B 00 74 36 01 13 8B 33 03 7B 04 57 51 52 53 FF B5 [2] FF FF FF B5 [2] FF FF 8B D6 8B CF 8B 85 [2] FF FF 05 AA 05 00 00 FF D0 5B 5A 59 5F 83 F9 00 74 05 83 C3 08 EB C5 }

	condition:
		$a0 at pe.entry_point
}
