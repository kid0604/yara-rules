import "pe"

rule Shrinkv10
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Shrinkv10 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 50 9C FC BE [2] BF [2] 57 B9 [2] F3 A4 8B [3] BE [2] BF [2] F3 A4 C3 }

	condition:
		$a0 at pe.entry_point
}
