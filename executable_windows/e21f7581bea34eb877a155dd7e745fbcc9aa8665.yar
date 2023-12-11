import "pe"

rule MinGWGCC3x
{
	meta:
		author = "malware-lu"
		description = "Detects MinGW GCC 3.x compiled executables"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 83 EC 08 C7 04 24 ?? 00 00 00 FF 15 [4] E8 [2] FF FF [8] 55 }

	condition:
		$a0 at pe.entry_point
}
