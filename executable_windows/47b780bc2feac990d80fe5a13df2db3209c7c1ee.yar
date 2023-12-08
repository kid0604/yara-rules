import "pe"

rule yCv13byAshkbizDanehkar
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC C0 00 00 00 53 56 57 8D BD 40 FF FF FF B9 30 00 00 00 B8 CC CC CC CC F3 AB 60 E8 00 00 00 00 5D 81 ED 84 52 41 00 B9 75 5E 41 00 81 E9 DE 52 41 00 8B D5 81 C2 DE 52 41 00 8D 3A 8B F7 33 C0 EB 04 90 EB 01 C2 AC }

	condition:
		$a0
}
