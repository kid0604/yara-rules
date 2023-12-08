import "pe"

rule VxModificationofHi924
{
	meta:
		author = "malware-lu"
		description = "Detects modification of Vx malware family"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 53 51 52 1E 06 9C B8 21 35 CD 21 53 BB [2] 26 [2] 49 48 5B }

	condition:
		$a0 at pe.entry_point
}
