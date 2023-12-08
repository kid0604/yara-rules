import "pe"

rule Litev003a
{
	meta:
		author = "malware-lu"
		description = "Detects Litev malware version 003a"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 06 FC 1E 07 BE [4] 6A 04 68 ?? 10 [2] 68 }

	condition:
		$a0 at pe.entry_point
}
