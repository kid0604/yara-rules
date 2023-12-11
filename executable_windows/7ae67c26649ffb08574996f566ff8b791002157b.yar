import "pe"

rule Petitev14
{
	meta:
		author = "malware-lu"
		description = "Detects Petite version 14 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 66 9C 60 50 8B D8 03 00 68 [4] 6A 00 }

	condition:
		$a0 at pe.entry_point
}
