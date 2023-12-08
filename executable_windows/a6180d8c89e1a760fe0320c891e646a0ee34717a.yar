import "pe"

rule Petitev212
{
	meta:
		author = "malware-lu"
		description = "Detects the Petite version 2.12 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 6A 00 68 [4] 64 [6] 64 [6] 66 9C 60 50 }

	condition:
		$a0 at pe.entry_point
}
