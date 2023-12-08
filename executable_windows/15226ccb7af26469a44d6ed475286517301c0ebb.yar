import "pe"

rule VxEddie2000
{
	meta:
		author = "malware-lu"
		description = "Detects VxEddie2000 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] FC 2E [4] 2E [4] 4D 5A [2] FA 8B E6 81 C4 [2] FB 3B [5] 50 06 56 1E 8B FE 33 C0 50 8E D8 C5 [3] B4 30 CD 21 }

	condition:
		$a0 at pe.entry_point
}
