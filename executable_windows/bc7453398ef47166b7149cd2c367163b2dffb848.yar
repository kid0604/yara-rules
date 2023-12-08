import "pe"

rule PECompactv094
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact v0.94 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 E8 [4] 5D 55 58 81 ED [4] 2B 85 [4] 01 85 [4] 50 B9 02 }

	condition:
		$a0 at pe.entry_point
}
