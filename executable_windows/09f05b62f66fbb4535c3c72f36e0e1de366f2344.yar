import "pe"

rule AlexProtectorv10Alex
{
	meta:
		author = "malware-lu"
		description = "Detects AlexProtector v1.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 81 ED 06 10 40 00 E8 24 00 00 00 EB 01 E9 8B }

	condition:
		$a0 at pe.entry_point
}
