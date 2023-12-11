import "pe"

rule Alloyv1x2000
{
	meta:
		author = "malware-lu"
		description = "Detects Alloy version 1x2000 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 07 20 40 ?? 87 DD 6A 04 68 ?? 10 [2] 68 ?? 02 [2] 6A ?? FF 95 46 23 40 ?? 0B }

	condition:
		$a0 at pe.entry_point
}
