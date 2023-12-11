import "pe"

rule HACKSTOPv113
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 52 B8 [2] 1E CD 21 86 E0 3D [2] 73 ?? CD 20 0E 1F B4 09 E8 [2] 24 ?? EA }

	condition:
		$a0 at pe.entry_point
}
