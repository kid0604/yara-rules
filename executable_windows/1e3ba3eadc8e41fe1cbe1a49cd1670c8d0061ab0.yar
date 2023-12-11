import "pe"

rule UnknownJoinersignfrompinch260320070212
{
	meta:
		author = "malware-lu"
		description = "Detects unknown joiner sign from pinch 260320070212"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 44 90 4C 90 B9 DE 00 00 00 BA 00 10 40 00 83 C2 03 44 90 4C B9 07 00 00 00 44 90 4C 33 C9 C7 05 08 30 40 00 00 00 00 00 90 68 00 01 00 00 68 21 30 40 00 6A 00 E8 C5 02 00 00 90 6A 00 68 80 }

	condition:
		$a0 at pe.entry_point
}
