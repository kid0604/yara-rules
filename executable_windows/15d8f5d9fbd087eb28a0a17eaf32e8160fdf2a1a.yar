import "pe"

rule PECompactv200alpha38
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact v2.00 alpha 38"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 80 B8 BF 10 00 10 01 74 7A C6 80 BF 10 00 10 01 9C 55 53 51 57 52 56 8D 98 0F 10 00 10 8B 53 14 8B E8 6A 40 68 00 10 00 00 FF 73 04 6A 00 8B 4B 10 03 CA 8B 01 FF D0 8B F8 50 8B 33 8B 53 14 03 F2 8B 4B 0C 03 CA 8D 85 B7 10 00 10 FF 73 04 8F }

	condition:
		$a0
}
