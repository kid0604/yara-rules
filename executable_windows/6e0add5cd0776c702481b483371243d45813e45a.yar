import "pe"

rule USSR031bySpirit
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of USSR031bySpirit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 5D 83 C5 12 55 C3 20 83 B8 ED 20 37 EF C6 B9 79 37 9E 8C C9 30 C9 E3 01 C3 BE 32 [3] B0 ?? 30 06 8A 06 46 81 FE 00 [3] 7C F3 }

	condition:
		$a0
}
