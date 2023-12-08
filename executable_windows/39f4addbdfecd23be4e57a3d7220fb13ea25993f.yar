import "pe"

rule VxEddie1028
{
	meta:
		author = "malware-lu"
		description = "Detects VxEddie1028 malware based on specific string at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E FC 83 [2] 81 [3] 4D 5A [2] FA 8B E6 81 C4 [2] FB 3B [5] 50 06 56 1E B8 FE 4B CD 21 81 FF BB 55 [2] 07 [3] 07 B4 49 CD 21 BB FF FF B4 48 CD 21 }

	condition:
		$a0 at pe.entry_point
}
