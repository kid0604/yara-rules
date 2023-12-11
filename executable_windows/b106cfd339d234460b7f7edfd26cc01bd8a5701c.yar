import "pe"

rule MSVisualCv8DLLhsmallsig1
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect MS Visual C v8 DLL with small signature 1"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B FF 55 8B EC 83 7D 0C 01 75 05 E8 [3] FF 5D E9 D6 FE FF FF CC CC CC CC CC }

	condition:
		$a0 at pe.entry_point
}
