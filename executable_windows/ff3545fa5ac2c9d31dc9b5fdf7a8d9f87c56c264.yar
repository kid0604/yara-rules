import "pe"

rule PESHiELDv0251
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PESHiELD version 0251"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5D 83 ED 06 EB 02 EA 04 8D }

	condition:
		$a0 at pe.entry_point
}
