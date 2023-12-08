import "pe"

rule PECompactv140b2v140b4
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact versions 1.40b2 and 1.40b4"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F A0 40 ?? 87 DD 8B 85 A6 A0 40 ?? 01 85 03 A0 40 ?? 66 C7 85 ?? A0 40 ?? 90 90 01 85 9E A0 40 ?? BB 86 11 }

	condition:
		$a0 at pe.entry_point
}
