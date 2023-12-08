import "pe"

rule Feokt
{
	meta:
		author = "malware-lu"
		description = "Detects Feokt malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 89 25 A8 11 40 00 BF [3] 00 31 C0 B9 [3] 00 29 F9 FC F3 AA [61] E8 }

	condition:
		$a0 at pe.entry_point
}
