import "pe"

rule SimbiOZ13Extranger
{
	meta:
		author = "malware-lu"
		description = "Detects the SimbiOZ13Extranger malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 57 57 8D 7C 24 04 50 B8 00 [3] AB 58 5F C3 }

	condition:
		$a0 at pe.entry_point
}
