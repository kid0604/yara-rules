import "pe"

rule kkrunchy023alpha2Ryd
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of kkrunchy023alpha2Ryd malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BD [4] C7 45 00 [3] 00 B8 [3] 00 89 45 04 89 45 54 50 C7 45 10 [3] 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF }
		$a1 = { BD [4] C7 45 00 [3] 00 B8 [3] 00 89 45 04 89 45 54 50 C7 45 10 [3] 00 FF 4D 0C FF 45 14 FF 45 58 C6 45 1C 08 B8 00 08 00 00 8D 7D 30 AB AB AB AB BB 00 00 D8 00 BF [3] 01 31 C9 41 8D 74 09 01 B8 CA 8E 2A 2E 99 F7 F6 01 C3 89 D8 C1 E8 15 AB FE C1 75 E8 BE }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
