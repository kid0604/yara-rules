import "pe"

rule VxIgor
{
	meta:
		author = "malware-lu"
		description = "Detects VxIgor malware based on entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 1E B8 CD 7B CD 21 81 FB CD 7B 75 03 E9 87 00 33 DB 0E 1F 8C }

	condition:
		$a0 at pe.entry_point
}
