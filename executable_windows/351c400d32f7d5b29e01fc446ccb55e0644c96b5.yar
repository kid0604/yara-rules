import "pe"

rule Nakedbind10nakedcrew
{
	meta:
		author = "malware-lu"
		description = "Detects the Nakedbind10nakedcrew malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 64 8B 38 48 8B C8 F2 AF AF 8B 1F 66 33 DB 66 81 3B 4D 5A 74 08 81 EB 00 00 }

	condition:
		$a0 at pe.entry_point
}
