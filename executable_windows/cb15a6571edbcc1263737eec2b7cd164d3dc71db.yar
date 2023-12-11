import "pe"

rule PECompactv110b1
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact v1.10b1 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 02 [3] 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 EB 28 63 40 ?? 87 DD 8B 85 AD 63 }

	condition:
		$a0 at pe.entry_point
}
