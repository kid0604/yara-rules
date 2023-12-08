import "pe"

rule PECompactv14x
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact version 1.4x"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

	condition:
		$a0 at pe.entry_point
}
