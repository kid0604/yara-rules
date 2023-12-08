import "pe"

rule PECompactv160v165
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact versions 1.60 and 1.65"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 3F 80 40 ?? 87 DD 8B 85 D2 80 40 ?? 01 85 33 80 40 ?? 66 C7 85 ?? 80 40 ?? 90 90 01 85 CE 80 40 ?? BB BB 12 }

	condition:
		$a0 at pe.entry_point
}
