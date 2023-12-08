import "pe"

rule PGMPACKv014
{
	meta:
		author = "malware-lu"
		description = "Detects PGMPACKv014 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E 17 50 B4 30 CD 21 3C 02 73 ?? B4 4C CD 21 FC BE [2] BF [2] E8 [2] E8 [2] BB [2] BA [2] 8A C3 8B F3 }

	condition:
		$a0 at pe.entry_point
}
