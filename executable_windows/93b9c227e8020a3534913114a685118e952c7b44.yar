import "pe"

rule NorthStarPEShrinkerv13byLiuxingping
{
	meta:
		author = "malware-lu"
		description = "Detects the NorthStar PE Shrinker v1.3 by Liuxingping"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00 2B E8 8D B5 73 ?? FF FF 8B 06 83 F8 00 74 11 8D B5 7F ?? FF FF 8B 06 83 F8 01 0F 84 F1 01 00 00 C7 06 01 00 00 00 8B D5 8B 85 4F ?? FF FF 2B D0 89 95 4F ?? FF FF 01 95 67 ?? FF FF 8D B5 83 ?? FF FF 01 }

	condition:
		$a0
}
