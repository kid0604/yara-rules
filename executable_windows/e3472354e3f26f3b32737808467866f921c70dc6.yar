import "pe"

rule AdysGluev010
{
	meta:
		author = "malware-lu"
		description = "Detects AdysGluev010 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2E 8C 06 [2] 0E 07 33 C0 8E D8 BE [2] BF [2] FC B9 [2] 56 F3 A5 1E 07 5F }

	condition:
		$a0 at pe.entry_point
}
