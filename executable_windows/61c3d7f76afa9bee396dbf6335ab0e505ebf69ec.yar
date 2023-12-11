import "pe"

rule PESHiELDv02v02bv02b2
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PESHiELDv02v02bv02b2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 41 4E 41 4B 49 4E 5D 83 ED 06 EB 02 EA 04 }

	condition:
		$a0 at pe.entry_point
}
