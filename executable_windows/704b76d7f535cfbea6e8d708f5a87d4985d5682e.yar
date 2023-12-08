import "pe"

rule WinUpackv039finalByDwingc2005h1
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting WinUpackv039finalByDwingc2005h1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE B0 11 [2] AD 50 FF 76 34 EB 7C 48 01 [2] 0B 01 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 00 18 10 00 00 10 00 00 00 00 [3] 00 00 [2] 00 10 00 00 00 02 00 00 04 00 00 00 00 00 39 00 04 00 00 00 00 00 00 00 00 [3] 00 02 00 00 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
