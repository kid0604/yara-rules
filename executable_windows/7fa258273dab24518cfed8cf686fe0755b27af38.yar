import "pe"

rule VxHymn1865
{
	meta:
		author = "malware-lu"
		description = "Detects VxHymn1865 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 83 EE 4C FC 2E [4] 4D 5A [2] FA 8B E6 81 [3] FB 3B [5] 2E [5] 50 06 56 1E 0E 1F B8 00 C5 CD 21 }

	condition:
		$a0 at pe.entry_point
}
