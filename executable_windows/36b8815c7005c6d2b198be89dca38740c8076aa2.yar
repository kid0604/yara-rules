import "pe"

rule eXpressorv12CGSoftLabs
{
	meta:
		author = "malware-lu"
		description = "Detects eXpressorv12CGSoftLabs malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 81 EC D4 01 00 00 53 56 57 EB 0C 45 78 50 72 2D 76 }

	condition:
		$a0 at pe.entry_point
}
