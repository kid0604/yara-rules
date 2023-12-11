import "pe"

rule PECompactv110b5
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact v1.10b5 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 0F 60 40 ?? 87 DD 8B 85 95 60 40 ?? 01 85 03 60 40 ?? 66 C7 85 ?? 60 40 ?? 90 90 BB 49 }

	condition:
		$a0 at pe.entry_point
}
