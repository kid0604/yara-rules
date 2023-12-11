import "pe"

rule PCPECalphapreview
{
	meta:
		author = "malware-lu"
		description = "Detects PCPECalphapreview malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00 }

	condition:
		$a0 at pe.entry_point
}
