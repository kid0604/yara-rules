import "pe"

rule Themida1201OreansTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects Themida or Oreans Technologies packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED [2] 35 09 89 95 [2] 35 09 89 B5 [2] 35 09 89 85 [2] 35 09 83 BD [2] 35 09 00 74 0C 8B E8 8B E2 B8 01 00 00 00 C2 0C 00 8B 44 24 24 89 85 [2] 35 09 6A 45 E8 A3 00 00 00 68 9A 74 83 07 E8 DF 00 00 00 68 25 }

	condition:
		$a0
}
