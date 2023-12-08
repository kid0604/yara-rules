import "pe"

rule PECompactv1242v1243
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact versions 1.24.2 and 1.24.3"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 A6 70 40 ?? 01 85 03 70 40 ?? 66 C7 85 70 40 90 ?? 90 01 85 9E 70 40 BB ?? D2 09 }

	condition:
		$a0 at pe.entry_point
}
