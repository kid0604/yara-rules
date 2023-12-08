import "pe"

rule VxQuake518
{
	meta:
		author = "malware-lu"
		description = "Detects VxQuake518 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E 06 8C C8 8E D8 [7] B8 21 35 CD 21 81 }

	condition:
		$a0 at pe.entry_point
}
