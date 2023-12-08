import "pe"

rule NsPackv23NorthStar
{
	meta:
		author = "malware-lu"
		description = "Detects the NsPackv23NorthStar malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [2] FF FF 8B 06 83 F8 00 74 11 8D B5 [2] FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 [2] FF FF 2B D0 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 8B 36 8B FD }
		$a1 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 8D B5 [2] FF FF 8B 06 83 F8 00 74 11 8D B5 [2] FF FF 8B 06 83 F8 01 0F 84 4B 02 00 00 C7 06 01 00 00 00 8B D5 8B 85 [2] FF FF 2B D0 89 95 [2] FF FF 01 95 [2] FF FF 8D B5 [2] FF FF 01 16 8B 36 8B FD 60 6A 40 68 00 10 00 00 68 00 10 00 00 6A 00 FF 95 [2] FF FF 85 C0 0F 84 56 03 00 00 89 85 [2] FF FF E8 00 00 00 00 5B B9 54 03 00 00 03 D9 50 53 E8 9D 02 00 00 61 }

	condition:
		$a0 or $a1
}
