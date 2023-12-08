import "pe"

rule Upack_UnknownDLLDwing
{
	meta:
		author = "malware-lu"
		description = "Detects unknown DLLs packed with Upack"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 09 00 00 00 17 CD 00 00 E9 06 02 }

	condition:
		$a0 at pe.entry_point
}
