import "pe"

rule PECompactv092
{
	meta:
		author = "malware-lu"
		description = "Detects PECompact version 0.92 packed files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 06 68 [4] C3 9C 60 BD [4] B9 02 [3] B0 90 8D BD A5 4F 40 ?? F3 AA 01 AD 04 51 40 ?? FF B5 }

	condition:
		$a0 at pe.entry_point
}
