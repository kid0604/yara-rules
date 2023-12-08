import "pe"

rule PECompactv120v1201
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact versions 1.20 and 1.201"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 70 40 ?? 87 DD 8B 85 9A 70 40 }

	condition:
		$a0 at pe.entry_point
}
