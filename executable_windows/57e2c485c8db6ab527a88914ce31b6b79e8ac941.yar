import "pe"

rule MSVisualCv8DLLhsmallsig2
{
	meta:
		author = "malware-lu"
		description = "Detects a specific small signature in Microsoft Visual C++ 8 DLL files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B FF 55 8B EC 53 8B 5D 08 56 8B 75 0C 85 F6 57 8B 7D 10 0F 84 [2] 00 00 83 FE 01 }

	condition:
		$a0 at pe.entry_point
}
