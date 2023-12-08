import "pe"

rule HEALTHv51byMuslimMPolyak
{
	meta:
		author = "malware-lu"
		description = "Detects HEALTHv51 malware by MuslimM and Polyak"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E E8 [2] 2E 8C 06 [2] 2E 89 3E [2] 8B D7 B8 [2] CD 21 8B D8 0E 1F E8 [2] 06 57 A1 [2] 26 }

	condition:
		$a0 at pe.entry_point
}
