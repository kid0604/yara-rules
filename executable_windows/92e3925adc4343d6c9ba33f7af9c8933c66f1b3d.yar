import "pe"

rule PECompactv0978
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact version 0.978"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 24 88 40 ?? 87 DD 8B 85 A9 88 }

	condition:
		$a0 at pe.entry_point
}
